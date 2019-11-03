-- Copyright (c) 2019  Herbert Valerio Riedel <hvr@gnu.org>
--
--  This file is free software: you may copy, redistribute and/or modify it
--  under the terms of the GNU General Public License as published by the
--  Free Software Foundation, either version 2 of the License, or (at your
--  option) any later version.
--
--  This file is distributed in the hope that it will be useful, but
--  WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
--  General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program (see `LICENSE`).  If not, see
--  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>.

{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- | String representation of LDAPv3 search 'Filter's as defined by <https://tools.ietf.org/html/rfc4515 RFC4515>.
--
-- @since 0.1.0
module LDAPv3.SearchFilter
  ( r'Filter
  , p'Filter
  ) where

import           Common                      hiding (many, option, some, (<|>))
import           LDAPv3.AttributeDescription
import           LDAPv3.Message

import qualified Data.ByteString             as BS
import qualified Data.List.NonEmpty          as NE
import qualified Data.Text                   as T
import qualified Data.Text.Encoding          as T
import           Data.Text.Lazy.Builder      as B
import           Data.Text.Lazy.Builder.Int  (hexadecimal)

import           Text.Parsec                 as P

-- -- | Render LDAPv3 search 'Filter's into <https://tools.ietf.org/html/rfc4515 RFC4515> text representation
-- renderFilter :: Filter -> Text
-- renderFilter = T.toStrict . B.toLazyText . r'Filter

r'Filter :: Filter -> Builder
r'Filter = r'filter
  where
    r'filter :: Filter -> Builder
    r'filter f0 = singleton '(' <> f' <> singleton ')'
      where
        f' = case f0 of
               Filter'and (SET1 fs)       -> singleton '&' <> sconcat (fmap r'filter fs)
               Filter'or  (SET1 fs)       -> singleton '|' <> sconcat (fmap r'filter fs)
               Filter'not f               -> singleton '!' <> r'filter f
               Filter'equalityMatch  ava  -> r'simple (singleton '=') ava
               Filter'greaterOrEqual ava  -> r'simple ">=" ava
               Filter'lessOrEqual    ava  -> r'simple "<=" ava
               Filter'approxMatch    ava  -> r'simple "~=" ava
               Filter'present attr        -> r'AttributeDescription attr <> "=*"
               Filter'substrings sub      -> r'substring sub
               Filter'extensibleMatch ext -> r'extensible ext


    r'simple :: Builder -> AttributeValueAssertion -> Builder
    r'simple filtertype (AttributeValueAssertion attr assertionvalue)
      = r'AttributeDescription attr <> filtertype <> r'assertionvalue assertionvalue

    r'substring :: SubstringFilter -> Builder
    r'substring (SubstringFilter attr (s1:|ss))
      = r'AttributeDescription attr <> singleton '=' <>
        (case s1 of
            Substring'initial x -> r'assertionvalue x <> go ss
            _                   -> go (s1:ss)
        )
      where
        go (Substring'initial _ : _)   = error "renderFilter: invalid SubstringFilter (misplaced 'initial')"
        go (Substring'final _ : _ : _) = error "renderFilter: invalid SubstringFilter (misplaced 'final')"
        go [Substring'final x]         = singleton '*' <> r'assertionvalue x
        go (Substring'any x : xs)      = singleton '*' <> r'assertionvalue x <> go xs
        go []                          = singleton '*'

    r'assertionvalue :: AssertionValue -> Builder
    r'assertionvalue bs
      | Right t <- T.decodeUtf8' bs = fromText (T.concatMap escT t)
      | otherwise = mconcat (map escB $ BS.unpack bs)
      where
        escT :: Char -> Text
        escT = \case
           -- minimal escaping
          '\x00' -> "\\00"
          '\x28' -> "\\28"
          '\x29' -> "\\29"
          '\x2a' -> "\\2a"
          '\x5c' -> "\\5c"
          c      -> T.singleton c

        escB :: Word8 -> Builder
        escB = \case
          0x00 -> "\\00"
          0x28 -> "\\28"
          0x29 -> "\\29"
          0x2a -> "\\2a"
          0x5c -> "\\5c"
          w | w < 0x80  -> singleton (toEnum (intCast w))
            | otherwise -> singleton '\\' <> hexadecimal w

    r'extensible :: MatchingRuleAssertion -> Builder
    r'extensible (MatchingRuleAssertion matchingrule attr assertionvalue dnattrs)
      | isNothing matchingrule, isNothing attr = "renderFilter: invalid MatchingRuleAssertion (matchingRule field absent and type field not present)"
      | otherwise = mconcat [ maybe mempty r'AttributeDescription attr
                            , if dnattrs then ":dn" else mempty
                            , maybe mempty (\mrid -> singleton ':' <> r'MatchingRuleId mrid) matchingrule
                            , ":=", r'assertionvalue assertionvalue
                            ]

-- TODO
-- -- | Parse <https://tools.ietf.org/html/rfc4515 RFC4515> string representation of a LDAPv3 search 'Filter's
-- parseFilter :: Text -> Either ParseError Filter
-- parseFilter = parse (parsecFilter <* eof) ""

-- | Parsec 'Parser' for parsing <https://tools.ietf.org/html/rfc4515 RFC4515> string representations of a LDAPv3 search 'Filter's
p'Filter :: Stream s Identity Char => Parsec s () Filter
p'Filter = p'filter
  where
    -- filter         = LPAREN filtercomp RPAREN
    p'filter = char '(' *> p'filtercomp <* char ')'

    -- filtercomp     = and / or / not / item
    --  and           = AMPERSAND filterlist
    --  or            = VERTBAR filterlist
    --  not           = EXCLAMATION filter
    p'filtercomp
      = choice [ Filter'and <$> (char '&' *> p'filterlist)
               , Filter'or  <$> (char '|' *> p'filterlist)
               , Filter'not <$> (char '!' *> p'filter)
               , p'item
               ]

    -- filterlist     = 1*filter
    p'filterlist = SET1 <$> some p'filter

    -- item            = simple / present / substring / extensible
    -- simple          = attr filtertype assertionvalue
    -- filtertype      = equal / approx / greaterorequal / lessorequal
    --  equal          = EQUALS
    --  approx         = TILDE EQUALS
    --  greaterorequal = RANGLE EQUALS
    --  lessorequal    = LANGLE EQUALS
    -- present         = attr EQUALS ASTERISK
    -- substring       = attr EQUALS [initial] any [final]
    --  initial        = assertionvalue
    --  any            = ASTERISK *(assertionvalue ASTERISK)
    --  final          = assertionvalue
    -- attr            = attributedescription
    --                     ; The attributedescription rule is defined in
    --                     ; Section 2.5 of [RFC4512].
    p'item = p'itemWithAttr <|> p'extensible Nothing

    p'itemWithAttr = do
      attr <- p'AttributeDescription <?> "attributedescription"

      choice [ Filter'approxMatch    . AttributeValueAssertion attr <$> (string "~=" *> p'assertionvalue)
             , Filter'greaterOrEqual . AttributeValueAssertion attr <$> (string ">=" *> p'assertionvalue)
             , Filter'lessOrEqual    . AttributeValueAssertion attr <$> (string "<=" *> p'assertionvalue)
             -- attr EQUALS ([initial] any [final] / assertionvalue)
             , char '=' *> (p'substringOrPresent attr
                            <|> (Filter'equalityMatch . AttributeValueAssertion attr <$> p'assertionvalue))
             -- attr [dnattrs] [matchingrule] COLON EQUALS assertionvalue
             , p'extensible (Just attr)
             ]

    -- extensible     = ( attr [dnattrs]
    --                      [matchingrule] COLON EQUALS assertionvalue )
    --                  / ( [dnattrs]
    --                       matchingrule COLON EQUALS assertionvalue )
    p'extensible mattr = do
      let _MatchingRuleAssertion'type = mattr
      _MatchingRuleAssertion'dnAttributes <- option False (True <$ p'dnattrs)
      _MatchingRuleAssertion'matchingRule <- case mattr of
        Nothing -> Just <$> p'matchingrule
        Just _  -> option Nothing (Just <$> try p'matchingrule)
      void (string ":=")
      _MatchingRuleAssertion'matchValue <- p'assertionvalue
      pure (Filter'extensibleMatch (MatchingRuleAssertion {..}))

    -- dnattrs        = COLON "dn"
    p'dnattrs = try (char ':' *> (char 'd' <|> char 'D') *> (char 'n' <|> char 'N') *> pure ())

    -- matchingrule   = COLON oid
    p'matchingrule = char ':' *> p'MatchingRuleId

    -- [assertionvalue] *(assertionvalue ASTERISK) [assertionvalue]
    p'substringOrPresent attr = try $ do
      let bs2lst x = if BS.null x then [] else [x]

      initial <- bs2lst <$> p'assertionvalue
      -- TODO: are empty fragments allowed? i.e. f** or ** ; according to ABNF it seems so
      anys    <- char '*' *> many (try (p'assertionvalue <* char '*'))
      final   <- bs2lst <$> p'assertionvalue

      pure $! case (Substring'initial <$> initial) ++
                   (Substring'any     <$> anys) ++
                   (Substring'final   <$> final) of
                []   -> Filter'present attr
                x:xs -> Filter'substrings (SubstringFilter attr (x:|xs))

    -- assertionvalue = valueencoding
    -- ; The <valueencoding> rule is used to encode an <AssertionValue>
    -- ; from Section 4.1.6 of [RFC4511].
    -- valueencoding  = 0*(normal / escaped)
    -- normal         = UTF1SUBSET / UTFMB
    -- escaped        = ESC HEX HEX
    -- UTF1SUBSET     = %x01-27 / %x2B-5B / %x5D-7F
    --                     ; UTF1SUBSET excludes 0x00 (NUL), LPAREN,
    --                     ; RPAREN, ASTERISK, and ESC.
    p'assertionvalue = deescape <$> many ((Right <$> satisfy (`notElem` ['\x00','(',')','*','\\'])) <|> Left <$> p'escaped)

    p'escaped = char '\\' *> ((\hi lo -> hi*16 + lo) <$> p'HEX <*> p'HEX)

    p'HEX = (fromIntegral :: Int -> Word8) . go . fromEnum <$> hexDigit
      where
        go n
          | n `inside` (0x30,0x39) = n - 0x30
          | n `inside` (0x61,0x66) = n - (0x61 - 10)
          | n `inside` (0x41,0x46) = n - (0x41 - 10)
          | otherwise              = undefined


----------------------------------------------------------------------------

deescape :: [Either Word8 Char] -> OCTET_STRING
deescape = mconcat . map go . groupEither
  where
    go (Left (x:|xs))  = BS.pack (x:xs)
    go (Right (c:|cs)) = T.encodeUtf8 (T.pack (c:cs))

groupEither :: [Either l r] -> [Either (NonEmpty l) (NonEmpty r)]
groupEither = \case
    [] -> []
    Left  l : rest -> goLeft  (l:|[]) rest
    Right r : rest -> goRight (r:|[]) rest
  where
    goLeft acc []               = Left (NE.reverse acc) : []
    goLeft acc (Left  l : rest) =                         goLeft (l<|acc) rest
    goLeft acc (Right r : rest) = Left (NE.reverse acc) : goRight (r:|[]) rest

    goRight acc []               = Right (NE.reverse acc) : []
    goRight acc (Left  l : rest) = Right (NE.reverse acc) : goLeft (l:|[]) rest
    goRight acc (Right r : rest) =                          goRight (r<|acc) rest

{-# INLINE some #-}
some :: Stream s m t => ParsecT s u m a -> ParsecT s u m (NonEmpty a)
some p = do
  xs0 <- many1 p
  case xs0 of
    []     -> fail "some': the impossible just happened"
    (x:xs) -> pure (x:|xs)
