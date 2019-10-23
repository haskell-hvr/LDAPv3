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

{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeOperators              #-}

module Data.ASN1.Prim
    ( TagPC(..)
    , TL
    , Tag(..)
    , TagK(..), KnownTag(..)
    , EncodingRule(..)
    , isolate64

    , putTagLength
    , getTagLength

    , getVarInt64
    , putVarInt64
    , asPrimitive

    , getVarInteger
    , putVarInteger
    ) where

import           Common

import           Data.Binary          as Bin
import           Data.Binary.Get      as Bin
import           Data.Binary.Put      as Bin

data TagPC
  = Primitive
  | Constructed
  deriving (Enum,Eq,Show)

data EncodingRule
  = BER
  | CER
  | DER
  deriving Eq

isolate64 :: Word64 -> Get a -> Get a
isolate64 sz64 act
  | Just sz <- intCastMaybe sz64 = Bin.isolate sz act
  | otherwise = fail "isolate64: exceeding supported limits"

type TL = (Tag, TagPC, Maybe Word64)

getTagLength :: EncodingRule -> Get (Maybe TL)
getTagLength r = do
  eof <- isEmpty

  if eof
    then pure Nothing
    else Just <$> do
      (t,pc) <- getTag r
      l <- getLength (r /= BER)

      case (r,l,pc) of
        (_,Nothing,Primitive)    -> fail "indefinite length not allowed for primitive encoding"
        (DER,Nothing,_)          -> fail "indefinite length encoding not allowed by DER"
        (CER,Just _,Constructed) -> fail "definite length not allowed for constructed encoding by CER"
        _                        -> pure ()

      pure (t,pc,l)

putTagLength :: TL -> PutM Word64
putTagLength (_,Primitive,Nothing) = error "indefinite length not allowed for primitive encoding"
putTagLength (t,pc,msz)            = (+) <$> putTag t pc <*> putLength msz

getTag :: EncodingRule -> Get (Tag, TagPC)
getTag _ = do
  b0 <- getWord8
  let !pc = if testBit b0 5 then Constructed else Primitive
      n0 = b0 .&. 0x1f

  !tn <- case n0 of
          0x1f -> getXTagNum -- long-form tag-number
          _    -> pure (fromIntegral n0)

  case b0 .&. 0xc0 of
    0x00 -> pure (Universal   tn, pc)
    0x40 -> pure (Application tn, pc)
    0x80 -> pure (Contextual  tn, pc)
    0xc0 -> pure (Private     tn, pc)
    _    -> fail "the impossible happened"

putTag :: Tag -> TagPC -> PutM Word64
putTag t pc = do
  when (tagNum t >= 31) $ error "putTag: FIXME"

  let w8_cls = case t of
                 Universal   _ -> 0x00
                 Application _ -> 0x40
                 Contextual  _ -> 0x80
                 Private     _ -> 0xc0

      w8_pc  = case pc of
                 Constructed -> 0x20
                 Primitive   -> 0x00

      w8_tn  = fromIntegral (tagNum t)

  putWord8 (w8_cls .|. w8_pc .|. w8_tn)
  pure 1

getXTagNum :: Get Word64
getXTagNum = do
    (more0,n0) <- getWord7
    let n0' = fromIntegral n0

    when (n0' == 0) $
      fail "lower 7 bits of the first subsequent tag-number octet shall not all be zero"

    if more0
      then go n0'
      else pure n0'

  where
    go :: Word64 -> Get Word64
    go !acc = do
      (mo,o7) <- getWord7
      let acc' = (acc `shiftL` 7) .|. fromIntegral o7

      when (acc >= 0x0200000000000000) $
        fail "tag number exceeds 64bit range" -- TODO: investigate whether there's ASN.1 schemas requiring larger tag-numbers

      if mo
        then go acc'
        else pure $! acc'

getWord7 :: Get (Bool,Word8)
getWord7 = do
  x <- getWord8
  let n = x .&. 0x7f
      more = x /= n
  pure (more, n)

getLength :: Bool -> Get (Maybe Word64) -- 'Nothing' denotes indefinite
getLength minimal = do
    xb7 <- getWord7
    case xb7 of
      -- definite short-form
      (False,n)   -> pure $! Just $! fromIntegral n

      -- indefinite
      (True,0)    -> pure Nothing

      -- reserved
      (True,0x7f) -> fail "length octet with reserved value 0xff encountered"

      -- definite long-form
      (True,sz)   -> Just <$> go sz 0
  where
    go :: Word8 -> Word64 -> Get Word64
    go 0 acc
      | minimal, acc < 0x1f  = fail "length not encoded minimally"
      | otherwise            = pure acc
    go sz acc = do
      when (acc >= 0x0100000000000000) $
        fail "length exceeds 64bit quantity"

      x <- getWord8

      let acc' = (acc `shiftL` 8) .|. fromIntegral x
      when (minimal && acc == 0 && x == 0) $
        fail "length not encoded minimally"

      go (sz-1) acc'

putLength :: Maybe Word64 -> PutM Word64
putLength Nothing = putWord8 0x80 *> pure 1
putLength (Just sz)
  | sz < 0x80 = putWord8 (fromIntegral sz) *> pure 1
  | otherwise = do
      let w8s = splitWord64 sz
          n   = length w8s

      putWord8 (0x80 + fromIntegral n)
      mapM_ putWord8 w8s
      pure (1 + fromIntegral n)


asPrimitive :: (Word64 -> Get x) -> TL -> Get x
asPrimitive _ (_,_,Nothing)         = fail "indefinite length not allowed"
asPrimitive _ (_,Constructed,_)     = fail "must be primitive"
asPrimitive f (_,Primitive,Just sz) = f sz

----------------------------------------------------------------------------

getInt24be :: Get Int32
getInt24be = do
  hi <- getInt8
  lo <- getWord16be
  pure $! (fromIntegral hi `shiftL` 16) + fromIntegral lo

getInt40be :: Get Int64
getInt40be = do
  hi <- getInt8
  lo <- getWord32be
  pure $! (fromIntegral hi `shiftL` 32) + fromIntegral lo

getInt48be :: Get Int64
getInt48be = do
  hi <- getInt16be
  lo <- getWord32be
  pure $! (fromIntegral hi `shiftL` 32) + fromIntegral lo

getInt56be :: Get Int64
getInt56be = do
  hi <- getInt24be
  lo <- getWord32be
  pure $! (fromIntegral hi `shiftL` 32) + fromIntegral lo


getVarInt64 :: Word64 -> Get Int64
getVarInt64 = \case
  0 -> fail "invalid zero-sized INTEGER"
  1 -> fromIntegral <$> getInt8
  2 -> fromIntegral <$> getInt16be
  3 -> fromIntegral <$> getInt24be
  4 -> fromIntegral <$> getInt32be
  5 ->                  getInt40be
  6 ->                  getInt48be
  7 ->                  getInt56be
  8 ->                  getInt64be
  _ -> fail "INTEGER too large for type"

getVarInteger :: Word64 -> Get Integer
getVarInteger sz
  | sz <= 8 = toInteger <$> getVarInt64 sz
  | otherwise = fail "INTEGER: FIXME/TODO"


putVarInt64 :: Int64 -> PutM Word64
putVarInt64 i = do
    mapM_ Bin.putWord8 w8s
    pure (fromIntegral $ length w8s)
  where
    w8s = splitInt64 i


putVarInteger :: Integer -> PutM Word64
putVarInteger j
  | Just i <- intCastMaybe j = putVarInt64 i
  | otherwise = error "putVarInteger: FIXME"

splitInt64 :: Int64 -> [Word8]
splitInt64 i
  | i >= 0x80 = goP i False []
  | i < -0x80 = goN i True  []
  | otherwise = [fromIntegral i]
  where
    goP 0 False acc = acc
    goP 0 True  acc = 0x00 : acc
    goP j _  acc = goP (j `shiftR` 8) (w8 >= 0x80) (w8 : acc)
      where w8 = fromIntegral (j .&. 0xff)

    goN (-1) True  acc = acc
    goN (-1) False acc = 0xff : acc
    goN j _        acc = goN (j `shiftR` 8) (w8 >= 0x80) (w8 : acc)
      where w8 = fromIntegral (j .&. 0xff)


splitWord64 :: Word64 -> [Word8]
splitWord64 i
  | i > 0xff  = go i []
  | otherwise = [fromIntegral i]
  where
    go 0 acc = acc
    go j acc = go (j `shiftR` 8) (w8 : acc)
      where w8 = fromIntegral (j .&. 0xff)


----------------------------------------------------------------------------

-- | ASN.1 Tag
data Tag = Universal   { tagNum :: !Word64 }
         | Application { tagNum :: !Word64 }
         | Contextual  { tagNum :: !Word64 }
         | Private     { tagNum :: !Word64 }
         deriving (Eq,Ord)

instance Show Tag where
  show = \case
     Universal n   -> "[UNIVERSAL "   ++ show n ++ "]"
     Application n -> "[APPLICATION " ++ show n ++ "]"
     Contextual n  -> "["             ++ show n ++ "]"
     Private n     -> "[PRIVATE "     ++ show n ++ "]"

----------------------------------------------------------------------------

-- | Type-level promoted 'Tag'
data TagK = UNIVERSAL   Nat
          | APPLICATION Nat
          | CONTEXTUAL  Nat
          | PRIVATE     Nat

class KnownTag (tag :: TagK) where
  tagVal :: Proxy tag -> Tag

instance forall n . (KnownNat n) => KnownTag ('UNIVERSAL n) where
  tagVal _ = Universal (fromIntegral $ natVal (Proxy :: Proxy n))

instance forall n . (KnownNat n) => KnownTag ('APPLICATION n) where
  tagVal _ = Application (fromIntegral $ natVal (Proxy :: Proxy n))

instance forall n . (KnownNat n) => KnownTag ('CONTEXTUAL n) where
  tagVal _ = Contextual (fromIntegral $ natVal (Proxy :: Proxy n))

instance forall n . (KnownNat n) => KnownTag ('PRIVATE n) where
  tagVal _ = Private (fromIntegral $ natVal (Proxy :: Proxy n))

----------------------------------------------------------------------------
