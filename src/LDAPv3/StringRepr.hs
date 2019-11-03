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

{-# LANGUAGE FlexibleContexts #-}

-- | String representation of LDAPv3 search 'Filter's as defined by <https://tools.ietf.org/html/rfc4515 RFC4515>.
--
-- @since 0.1.0
module LDAPv3.StringRepr
    ( StringRepr ( asParsec
             , asBuilder
             , renderShortText
             )
    , renderText
    , renderString
    , parseShortText
    , parseText
    , parseString
    ) where

import           Common                      hiding (Option, many, option, some, (<|>))

import qualified Data.Text.Lazy              as T (toStrict)
import           Data.Text.Lazy.Builder      as B
import qualified Data.Text.Short             as TS
import           Text.Parsec                 as P

import           LDAPv3.AttributeDescription
import           LDAPv3.Message              (Filter)
import           LDAPv3.SearchFilter

-- | Convert to and from string representations as defined by <https://tools.ietf.org/html/rfc4515 RFC4515>.
--
-- @since 0.1.0
class StringRepr a where
  asParsec :: Stream s Identity Char => Parsec s () a

  asBuilder :: a -> Builder
  asBuilder = fromText . TS.toText . renderShortText

  renderShortText :: a -> ShortText
  renderShortText = TS.fromText . T.toStrict . B.toLazyText . asBuilder

  {-# MINIMAL asParsec, (renderShortText | asBuilder) #-}

-- | Convenience 'StringRepr' operation for rendering as 'Text'
--
-- @since 0.1.0
renderText :: StringRepr a => a -> Text
renderText = TS.toText . renderShortText

-- | Convenience 'StringRepr' operation for rendering as plain-old 'String'
--
-- @since 0.1.0
renderString :: StringRepr a => a -> String
renderString = TS.toString . renderShortText

-- | Convenience 'StringRepr' operation for parsing from 'Text'
--
-- @since 0.1.0
parseText :: StringRepr a => Text -> Maybe a
parseText = either (const Nothing) Just . parse (asParsec <* eof) ""

-- | Convenience 'StringRepr' operation for parsing from 'ShortText'
--
-- @since 0.1.0
parseShortText :: StringRepr a => ShortText -> Maybe a
parseShortText = either (const Nothing) Just . parse (asParsec <* eof) "" . TS.toString

-- | Convenience 'StringRepr' operation for parsing from plain-old 'String'
--
-- @since 0.1.0
parseString :: StringRepr a => String -> Maybe a
parseString = either (const Nothing) Just . parse (asParsec <* eof) ""

instance StringRepr AttributeDescription where
  asParsec    = p'AttributeDescription
  renderShortText = ts'AttributeDescription

instance StringRepr Option where
  asParsec    = p'Option
  renderShortText = ts'Option

instance StringRepr OID where
  asBuilder   = r'OID
  renderShortText = ts'OID
  asParsec    = p'OID

instance StringRepr KeyString where
  asParsec    = p'KeyString
  renderShortText = ts'KeyString

instance StringRepr MatchingRuleId where
  asParsec    = p'MatchingRuleId
  renderShortText = ts'MatchingRuleId

instance StringRepr Filter where
  asBuilder = r'Filter
  asParsec  = p'Filter
