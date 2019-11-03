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

{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}

-- internal module
module LDAPv3.AttributeDescription
    ( AttributeDescription(..)
    , p'AttributeDescription
    , ts'AttributeDescription
    , r'AttributeDescription

    , Option
    , p'Option
    , ts'Option

    , KeyString
    , p'KeyString
    , ts'KeyString

    , MatchingRuleId(..)
    , p'MatchingRuleId
    , ts'MatchingRuleId
    , r'MatchingRuleId

    , OID(..)
    , p'OID
    , ts'OID
    , r'OID
    ) where

import           Common                 hiding (Option, many, option, some, (<|>))
import           Data.ASN1

import qualified Data.ByteString.Char8  as BSC
import qualified Data.ByteString.Short  as SBS
import           Data.Char              (isDigit, toLower)
import           Data.List
import           Data.Set               (Set)
import qualified Data.Set               as Set
import qualified Data.String            as S
import           Data.Text.Lazy.Builder as B
import qualified Data.Text.Short        as TS
import           Text.Parsec            as P

{- | Attribute Descriptions  (<https://tools.ietf.org/html/rfc4511#section-4.1.4 RFC4511 Section 4.1.4>)

> AttributeDescription ::= LDAPString
>                         -- Constrained to <attributedescription>
>                         -- [RFC4512]

@attributedescription@'s syntax is defined in ABNF (<https://tools.ietf.org/search/rfc4234 RFC4234>) notation as

> attributedescription = attributetype options
> attributetype = oid
> options = *( SEMI option )
> option = 1*keychar
> oid = descr / numericoid
>
> descr = keystring
> numericoid = number 1*( DOT number )
> keystring = leadkeychar *keychar
> leadkeychar = ALPHA
> keychar = ALPHA / DIGIT / HYPHEN
> ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
> number  = DIGIT / ( LDIGIT 1*DIGIT )
> DIGIT   = %x30 / LDIGIT       ; "0"-"9"
> LDIGIT  = %x31-39             ; "1"-"9"
> HYPHEN  = %x2D                ; hyphen ("-")

See also <https://tools.ietf.org/search/rfc4512#section-2.5 RFC4512 Section 2.5> for the definition of @attributedescription@.

-}
data AttributeDescription = AttributeDescription (Either KeyString OID) (Set Option)
  deriving (Eq,Ord,Show,Generic)

instance NFData AttributeDescription where
  rnf (AttributeDescription k o) = rnf (k,o)

instance ASN1 AttributeDescription where
  asn1defTag _ = asn1defTag (Proxy :: Proxy OCTET_STRING)
  asn1decode = asn1decodeParsec "AttributeDescription" p'AttributeDescription
  asn1encode = asn1encode . ts'AttributeDescription

instance S.IsString AttributeDescription where
  fromString = _fromString "AttributeDescription" p'AttributeDescription

_fromString :: Stream s Identity Char => [Char] -> ParsecT s () Identity x -> s -> x
_fromString l p = either (error ("invalid " ++ l ++ " string literal")) id . parse (p <* eof) ""

-- attributedescription = attributetype options
-- attributetype = oid
p'AttributeDescription :: Stream s Identity Char => Parsec s () AttributeDescription
p'AttributeDescription = AttributeDescription <$> p'DescrOrOID <*> (Set.fromList <$> p'options)
  where
    -- options = *( SEMI option )
    p'options = many (char ';' *> p'Option)

r'AttributeDescription :: AttributeDescription -> Builder
r'AttributeDescription = b'ShortText . ts'AttributeDescription

ts'AttributeDescription :: AttributeDescription -> ShortText
ts'AttributeDescription (AttributeDescription key opts)
  | Set.null opts = k
  | otherwise = TS.intercalate ";" (k:[ o | Option o <- Set.toList opts])
  where
    k = ts'DescrOrOID key

{- | Case-insensitive attribute description option

> option = 1*keychar
> keychar = ALPHA / DIGIT / HYPHEN
> ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
> DIGIT   = %x30 / LDIGIT       ; "0"-"9"
> HYPHEN  = %x2D                ; hyphen ("-")

-}
newtype Option = Option ShortText
  deriving (NFData)

instance Eq Option where
  Option x == Option y = x `eqCI` y

instance Ord Option where
  Option x `compare` Option y = x `cmpCI` y

instance Show Option where
  showsPrec p (Option s) = showsPrec p s
  show (Option s) = show s

instance S.IsString Option where
  fromString = _fromString "Option" p'Option

-- option = 1*keychar
p'Option :: Stream s Identity Char => Parsec s () Option
p'Option = Option . TS.fromString <$> many1 p'keychar

ts'Option :: Option -> ShortText
ts'Option (Option s) = s

-- oid = descr / numericoid
-- descr = keystring
p'DescrOrOID :: Stream s Identity Char => Parsec s () (Either KeyString OID)
p'DescrOrOID = ((Left <$> p'KeyString) <|> (Right <$> p'OID)) <?> "oid"

ts'DescrOrOID :: Either KeyString OID -> ShortText
ts'DescrOrOID = \case
  Left (KeyString s) -> s
  Right oid          -> TS.fromString (s'OID oid)

{- | Numeric Object Identifier (OID)

> numericoid = number 1*( DOT number )
> number  = DIGIT / ( LDIGIT 1*DIGIT )
> DIGIT   = %x30 / LDIGIT       ; "0"-"9"
> LDIGIT  = %x31-39             ; "1"-"9"

-}
newtype OID = OID (NonEmpty Natural)
  deriving (Eq,Ord,Show,NFData)

instance Newtype OID (NonEmpty Natural)

instance ASN1 OID where
  asn1defTag _ = asn1defTag (Proxy :: Proxy OCTET_STRING)
  asn1encode oid = asn1encode (BSC.pack (s'OID oid))
  asn1decode = asn1decodeParsec "OID" p'OID

r'OID :: OID -> Builder
r'OID = B.fromString . s'OID

ts'OID :: OID -> ShortText
ts'OID = TS.fromString . s'OID

s'OID :: OID -> String
s'OID (OID (x:|xs)) = intercalate "." (map show (x:xs))


p'OID :: Stream s Identity Char => Parsec s () OID
p'OID = p'numericoid
  where
    -- numericoid = number 1*( DOT number )
    p'numericoid = OID <$> (p'number `sepBy1'` char '.')

    -- number  = DIGIT / ( LDIGIT 1*DIGIT )
    -- DIGIT   = %x30 / LDIGIT       ; "0"-"9"
    -- LDIGIT  = %x31-39             ; "1"-"9"
    p'number = do
      ldigit <- digit
      if ldigit == '0'
         then pure 0
         else read . (ldigit:) <$> many digit

    sepBy1' p set = f <$> sepBy1 p set
      where
        f []     = error "the impossible happened"
        f (x:xs) = x:|xs

{- | Case-insensitive string used to denote OID short names

> keystring = leadkeychar *keychar
> leadkeychar = ALPHA
> keychar = ALPHA / DIGIT / HYPHEN
> ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
> DIGIT   = %x30 / LDIGIT       ; "0"-"9"
> HYPHEN  = %x2D                ; hyphen ("-")

-}
newtype KeyString = KeyString ShortText
  deriving (NFData)

instance Eq KeyString where
  KeyString x == KeyString y = x `eqCI` y

instance Ord KeyString where
  KeyString x `compare` KeyString y = x `cmpCI` y

instance Show KeyString where
  showsPrec p (KeyString s) = showsPrec p s
  show (KeyString s) = show s

instance S.IsString KeyString where
  fromString = _fromString "KeyString" p'KeyString

ts'KeyString :: KeyString -> ShortText
ts'KeyString (KeyString s) = s

p'KeyString :: Stream s Identity Char => Parsec s () KeyString
p'KeyString = KeyString . TS.fromString <$> p'keystring
  where
    -- keystring = leadkeychar *keychar
    -- leadkeychar = ALPHA
    p'keystring = (:) <$> p'ALPHA <*> many p'keychar

    -- ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
    p'ALPHA = satisfy (\c -> (c `inside` ('A','Z')) || (c `inside` ('a','z'))) <?> "ALPHA"


-- keychar = ALPHA / DIGIT / HYPHEN
p'keychar :: Stream s Identity Char => Parsec s () Char
p'keychar = satisfy (\c -> (c `inside` ('A','Z')) || (c `inside` ('a','z')) || isDigit c || c == '-')


b'ShortText :: ShortText -> Builder
b'ShortText = fromText . TS.toText

{- | Matching Rule Identifier  (<https://tools.ietf.org/html/rfc4511#section-4.1.8 RFC4511 Section 4.1.8>)

> MatchingRuleId ::= LDAPString

-}
newtype MatchingRuleId = MatchingRuleId (Either KeyString OID)
  deriving (Generic,Show,Eq,Ord,NFData)

instance ASN1 MatchingRuleId where
  asn1defTag _ = asn1defTag (Proxy :: Proxy OCTET_STRING)
  asn1encode (MatchingRuleId v) = asn1encode (ts'DescrOrOID v)
  asn1decode = asn1decodeParsec "MatchingRuleId" p'MatchingRuleId

instance S.IsString MatchingRuleId where
  fromString = _fromString "MatchingRuleId" p'MatchingRuleId

ts'MatchingRuleId :: MatchingRuleId -> ShortText
ts'MatchingRuleId (MatchingRuleId mrid) = ts'DescrOrOID mrid

r'MatchingRuleId :: MatchingRuleId -> Builder
r'MatchingRuleId = b'ShortText . ts'MatchingRuleId

p'MatchingRuleId :: Stream s Identity Char => Parsec s () MatchingRuleId
p'MatchingRuleId = MatchingRuleId <$> p'DescrOrOID



eqCI :: ShortText -> ShortText -> Bool
eqCI x y
  | x == y = True
  | SBS.length (TS.toShortByteString x) /= SBS.length (TS.toShortByteString y) = False
  | otherwise = map toLower (TS.toString x) == map toLower (TS.toString y)

cmpCI :: ShortText -> ShortText -> Ordering
cmpCI x y
  | x == y = EQ
  | otherwise = map toLower (TS.toString x) `compare` map toLower (TS.toString y)
