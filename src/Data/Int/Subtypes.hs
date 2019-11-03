-- Copyright (c) 2018-2019  Herbert Valerio Riedel <hvr@gnu.org>
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

{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE UndecidableInstances #-}

module Data.Int.Subtypes
    ( UInt(..), toUInt, toUInt', fromUInt, uintFromInteger
    , SInt(..), toSInt, fromSInt, sintFromInteger

    , UIntBounds
    , SIntBounds

      -- helpers
    , IsBelowMaxBound
    , IsAboveMinBoundNeg
    ) where

import           Common

import           Data.Coerce (coerce)

-- | Unsigned integer sub-type
newtype UInt (lb :: Nat) (ub :: Nat) t = UInt t
  deriving (Eq,Ord)

-- | Signed integer sub-type
--
-- __NOTE__: Due to lack of negative type-level integer literals the
-- lower bound is negated, i.e. it expresses a negative magnitude
newtype SInt (nlb :: Nat) (ub :: Nat) t = SInt t
  deriving (Eq,Ord)

-- | Coerce integer sub-type into its base-type
fromUInt :: UInt lb ub t -> t
fromUInt (UInt i) = i

-- | Coerce integer sub-type into its base-type
fromSInt :: SInt nlb ub t -> t
fromSInt (SInt i) = i

instance forall lb ub t . NFData t => NFData (UInt lb ub t) where
  rnf = coerce (rnf :: t -> ())

instance forall lb ub t . NFData t => NFData (SInt lb ub t) where
  rnf = coerce (rnf :: t -> ())

instance forall lb ub t . Show t => Show (UInt lb ub t) where
  show      = coerce (show :: t -> String)
  showsPrec = coerce (showsPrec :: Int -> t -> ShowS)

instance forall nlb ub t . Show t => Show (SInt nlb ub t) where
  show      = coerce (show :: t -> String)
  showsPrec = coerce (showsPrec :: Int -> t -> ShowS)

-- | Constraint encoding type-level invariants for 'UInt'
type UIntBounds lb ub t = ( KnownNat lb, KnownNat ub, lb <= ub
                          , IsBelowMaxBound ub (IntBaseType t) ~ 'True)

-- | Constraint encoding type-level invariants for 'SInt'
type SIntBounds nlb ub t = ( KnownNat nlb, KnownNat ub
                          , IsAboveMinBoundNeg nlb (IntBaseType t) ~ 'True
                          , IsBelowMaxBound ub (IntBaseType t) ~ 'True)

type family IsBelowMaxBound (n :: Nat) (t :: IntBaseTypeK) :: Bool where
  IsBelowMaxBound n ('FixedWordTag b) = n+1 <=? (2^b)
  IsBelowMaxBound n ('FixedIntTag b)  = n+1 <=? (2^(b-1))
  IsBelowMaxBound n 'BigIntTag        = 'True
  IsBelowMaxBound n 'BigWordTag       = 'True

type family IsAboveMinBoundNeg (n :: Nat) (t :: IntBaseTypeK) :: Bool where
  IsAboveMinBoundNeg n ('FixedWordTag b) = n <=? 0
  IsAboveMinBoundNeg n ('FixedIntTag b)  = n <=? (2^(b-1))
  IsAboveMinBoundNeg n 'BigIntTag        = 'True
  IsAboveMinBoundNeg n 'BigWordTag       = n <=? 0

instance forall lb ub t . (UIntBounds lb ub t, Num t) => Bounded (UInt lb ub t) where
  minBound = UInt $ fromInteger (natVal (Proxy :: Proxy lb))
  maxBound = UInt $ fromInteger (natVal (Proxy :: Proxy ub))

instance forall nlb ub t . (SIntBounds nlb ub t, Num t) => Bounded (SInt nlb ub t) where
  minBound = SInt $ fromInteger (-natVal (Proxy :: Proxy nlb))
  maxBound = SInt $ fromInteger (natVal (Proxy :: Proxy ub))

----------------------------------------------------------------------------

uintFromInteger :: forall lb ub t . (UIntBounds lb ub t, Num t) => Integer -> Either ArithException (UInt lb ub t)
uintFromInteger i
  | i < natVal (Proxy :: Proxy lb) = Left Underflow
  | i > natVal (Proxy :: Proxy ub) = Left Overflow
  | otherwise                      = Right i'
  where
    i' = UInt (fromInteger i) :: UInt lb ub t

-- | Try to coerce a base-type into its 'UInt' sub-type
--
-- If out of range, @'Left' 'Underflow'@ or @'Left' 'Overflow'@ will be returned respectively.
toUInt :: forall lb ub t . (UIntBounds lb ub t, Num t, Ord t) => t -> Either ArithException (UInt lb ub t)
toUInt i
  | i' < minBound = Left Underflow
  | i' > maxBound = Left Overflow
  | otherwise     = Right i'
  where
    i' = UInt i :: UInt lb ub t

toUInt' :: forall lb ub t . (UIntBounds lb ub t, Num t, Ord t) => t -> UInt lb ub t
toUInt' = either throw id . toUInt

instance forall lb ub t . (UIntBounds lb ub t, Integral t, Ord t) => Num (UInt lb ub t) where
  fromInteger     = either throw id . uintFromInteger

  UInt 0 * _      = UInt 0
  UInt 1 * y      = y
  _      * UInt 0 = UInt 0
  x      * UInt 1 = x
  UInt x * UInt y = fromInteger (toInteger x * toInteger y)

  UInt 0 + y      = y
  x      + UInt 0 = x
  UInt x + UInt y = fromInteger (toInteger x + toInteger y)

  x      - UInt 0 = x
  UInt 0 - y      = negate y
  UInt x - UInt y = fromInteger (toInteger x - toInteger y)

  negate (UInt 0) = UInt 0
  negate (UInt _) = throw Underflow

  abs             = id

  signum (UInt 0) = UInt 0
  signum (UInt _) = toUInt' 1

----------------------------------------------------------------------------

sintFromInteger :: forall nlb ub t . (SIntBounds nlb ub t, Num t) => Integer -> Either ArithException (SInt nlb ub t)
sintFromInteger i
  | i < -natVal (Proxy :: Proxy nlb) = Left Underflow
  | i >  natVal (Proxy :: Proxy ub)  = Left Overflow
  | otherwise                        = Right i'
  where
    i' = SInt (fromInteger i) :: SInt nlb ub t

-- | Try to coerce a base-type into its 'SInt' sub-type
--
-- If out of range, @'Left' 'Underflow'@ or @'Right' 'Overflow'@ will be returned.
toSInt :: forall nlb ub t . (SIntBounds nlb ub t, Num t, Ord t) => t -> Either ArithException (SInt nlb ub t)
toSInt i
  | i' < minBound = Left Underflow
  | i' > maxBound = Left Overflow
  | otherwise     = Right i'
  where
    i' = SInt i :: SInt nlb ub t

toSInt' :: forall nlb ub t . (SIntBounds nlb ub t, Num t, Ord t) => t -> SInt nlb ub t
toSInt' = either throw id . toSInt

instance forall nlb ub t . (SIntBounds nlb ub t, Integral t, Ord t) => Num (SInt nlb ub t) where
  fromInteger     = either throw id . sintFromInteger

  SInt 0 * _      = SInt 0
  SInt 1 * y      = y
  _      * SInt 0 = SInt 0
  x      * SInt 1 = x
  SInt x * SInt y = fromInteger (toInteger x * toInteger y)

  SInt 0 + y      = y
  x      + SInt 0 = x
  SInt x + SInt y = fromInteger (toInteger x + toInteger y)

  x      - SInt 0 = x
  SInt 0 - y      = negate y
  SInt x - SInt y = fromInteger (toInteger x - toInteger y)

  negate (SInt 0) = SInt 0
  negate (SInt x) = fromInteger (toInteger x)

  abs    (SInt x) = fromInteger (abs (toInteger x))

  signum (SInt 0) = SInt 0
  signum (SInt x) = toSInt' (signum x)
