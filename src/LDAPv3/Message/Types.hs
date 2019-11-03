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

{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module LDAPv3.Message.Types where

import           Common
import           Data.ASN1         (ASN1)
import           Data.Int.Subtypes

{- | LDAPv3 protocol ASN.1 constant as per <https://tools.ietf.org/html/rfc4511#section-4.1.1 RFC4511 Section 4.1.1>

> maxInt INTEGER ::= 2147483647 -- (2^^31 - 1)

-}
type MaxInt = 2147483647

{- | Message ID (<https://tools.ietf.org/html/rfc4511#section-4.1.1.1 RFC4511 Section 4.1.1.1>)

> MessageID ::= INTEGER (0 ..  maxInt)

-}
newtype MessageID = MessageID (UInt 0 MaxInt Int32)
                  deriving (Generic,NFData,Ord,Bounded,Show,Eq,ASN1)

instance Newtype MessageID (UInt 0 MaxInt Int32)

-- | @since 0.1.0
instance Enum MessageID where
  succ (MessageID i) = MessageID (i+1)
  pred (MessageID i) = MessageID (i-1)

  fromEnum (MessageID i) = intCast (fromUInt i)

  toEnum i
    | i < 0          = throw Underflow
    | i > 0x7fffffff = throw Overflow
    | otherwise      = MessageID (toUInt' (fromIntegral i))

  enumFrom     x   = enumFromTo     x maxBound
  enumFromThen x y = enumFromThenTo x y bound
    where
      bound | y >= x     = maxBound
            | otherwise  = minBound
