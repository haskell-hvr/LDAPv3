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

{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE TypeOperators              #-}

module Data.ASN1
    ( ASN1(..)
    , ASN1Decode
    , ASN1Encode

    , ENUMERATED(..), Enumerated(..)
    , IMPLICIT(..), implicit
    , EXPLICIT(..), explicit

    , OCTET_STRING
    , NULL
    , BOOLEAN
    , BOOLEAN_DEFAULT(..)
    , OPTIONAL

    , SET(..)
    , SET1(..)

    , toBinaryPut
    , toBinaryGet

    , retag, wraptag

    , dec'SEQUENCE
    , enc'SEQUENCE
    , enc'SEQUENCE_COMPS

    , dec'SET_OF
    , dec'SEQUENCE_OF

    , dec'CHOICE
    , dec'OPTIONAL

    , dec'BoundedEnum
    , enc'BoundedEnum

    , dec'NULL
    , enc'NULL
    ) where

import           Common
import           Data.ASN1.Prim
import           Data.Int.Subtypes

import           Data.Binary           as Bin
import           Data.Binary.Get       as Bin
import           Data.Binary.Put       as Bin
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Short as SBS
import qualified Data.Map.Strict       as Map
import           Data.Set              (Set)
import qualified Data.Set              as Set
import           Data.String           (IsString)
import qualified Data.Text.Short       as TS

----------------------------------------------------------------------------

class Enumerated x where
  toEnumerated :: Int64 -> Maybe x
  fromEnumerated :: x -> Int64

instance Enumerated Int64 where
  toEnumerated = Just
  fromEnumerated = id

instance Enumerated Int where
  toEnumerated = intCastMaybe
  fromEnumerated = intCast

----------------------------------------------------------------------------

newtype ASN1Encode a = ASN1Encode (Maybe Tag -> PutM a)

empty'ASN1Encode :: ASN1Encode Word64
empty'ASN1Encode = ASN1Encode $ \case
  Just _  -> error "empty'ASN1Encode: called with tag-override"
  Nothing -> pure 0

toBinaryPut :: ASN1Encode a -> PutM a
toBinaryPut (ASN1Encode body) = body Nothing

enc'SEQUENCE_COMPS :: [ASN1Encode Word64] -> ASN1Encode Word64
enc'SEQUENCE_COMPS [] = empty'ASN1Encode
enc'SEQUENCE_COMPS xs0 = ASN1Encode $ \case
    Just _  -> error "enc'SEQUENCE_COMPS: called with tag-override"
    Nothing -> go xs0 0
  where
    go [] sz = pure sz
    go (ASN1Encode x:xs) sz = do
      n1 <- x Nothing
      go xs (sz+n1)

enc'SEQUENCE :: [ASN1Encode Word64] -> ASN1Encode Word64
enc'SEQUENCE = wraptag (Universal 16) . enc'SEQUENCE_COMPS

enc'SET :: [ASN1Encode Word64] -> ASN1Encode Word64
enc'SET = retag (Universal 17) . enc'SEQUENCE

----------------------------------------------------------------------------

data ASN1Res x = Consumed ({- leftover -} Maybe TL) x
               | Unexpected {- leftover -} TL
               | UnexpectedEOF
               deriving (Show,Functor)

data Card = Card {- min -} !Word {- delta -} !Word
          deriving (Eq,Ord,Show)

cardMaySkip :: Card -> Bool
cardMaySkip (Card 0 _) = True
cardMaySkip (Card _ _) = False

-- addition
instance Semigroup Card where
  Card l1 u1 <> Card l2 u2 = Card (l1+l2) (u1+u2)

instance Monoid Card where
  mappend = (<>)
  mempty  = Card 0 0

data ASN1Decode x = ASN1Decode
  { asn1dTags    :: !(Set Tag)  --
  , asn1dAny     :: !Bool       -- declare which tags asn1dContent is possibly going to handle
  , asn1dCard    :: !Card -- lower&upper bounds of how many items asn1dCard is going to consume
  , asn1dContent :: Maybe TL -> Get (ASN1Res x) -- 'Nothing' argument denotes EOF/EOC
  }

getASN1Decode :: ASN1Decode x -> Maybe TL -> Get (ASN1Res x)
getASN1Decode (ASN1Decode{..}) Nothing
  | cardMaySkip asn1dCard              = asn1dContent Nothing
  | otherwise                          = pure UnexpectedEOF
getASN1Decode (ASN1Decode{..}) (Just tl@(t,_,_))
  | cardMaySkip asn1dCard || asn1dAny || Set.member t asn1dTags = asn1dContent (Just tl)
  | otherwise                          = pure (Unexpected tl)

-- | "CHOICE" join
instance Alternative ASN1Decode where
  empty = ASN1Decode mempty False mempty (pure . maybe UnexpectedEOF Unexpected)
  x <|> y
    | asn1decodeIsEmpty x = y
    | asn1decodeIsEmpty y = x
    | asn1dCard x /= asn1dCard y = error' "ASN1Decode: CHOICE over different cardinalities not supported"
    | asn1dAny x, asn1dAny y = error' "ASN1Decode: CHOICE not possible over multiple ANYs"
    | cardMaySkip (asn1dCard x) || cardMaySkip (asn1dCard y) = error' "ASN1Decode: CHOICE over OPTIONAL not supported"
    | not (Set.null (asn1dTags x `Set.intersection` asn1dTags y)) = error' "ASN1Decode: CHOICEs overlap"
    | otherwise = ASN1Decode
                  { asn1dTags = asn1dTags x <> asn1dTags y
                  , asn1dAny  = asn1dAny x || asn1dAny y
                  , asn1dCard = asn1dCard x
                  , asn1dContent = \case
                          tl@(Just tl'@(t,_,_)) -> case () of
                            _ | Set.member t (asn1dTags x) -> asn1dContent x tl
                              | Set.member t (asn1dTags y) -> asn1dContent y tl
                              | asn1dAny x -> asn1dContent x tl
                              | asn1dAny y -> asn1dContent y tl
                              | otherwise  -> pure (Unexpected tl')
                          Nothing -> pure UnexpectedEOF -- CHOICEs are allowed only among non-OPTIONALs
                  }
    where
      error' s = error (s ++ " => " ++ show ((asn1dTags x, asn1dAny x, asn1dCard x), (asn1dTags y, asn1dAny y, asn1dCard y)))


asum'ASN1Decode :: [ASN1Decode x] -> ASN1Decode x
asum'ASN1Decode xs0
  | Map.size tagmap /= sum (map (Set.size . asn1dTags) xs) = error' "ASN1Decode: CHOICEs overlap"
  | x0:_ <- xs = ASN1Decode { asn1dTags = mconcat (map asn1dTags xs)
                            , asn1dAny  = any asn1dAny xs
                            , asn1dCard = asn1dCard x0
                            , asn1dContent = \case
                                    tl@(Just tl'@(t,_,_)) -> case () of
                                      _ | Just h <- Map.lookup t tagmap -> h tl
                                        | otherwise -> anydispatch tl'
                                    Nothing -> pure UnexpectedEOF -- CHOICEs are allowed only among non-OPTIONALs
                            }
  | otherwise = empty
  where
    xs = filter (not . asn1decodeIsEmpty) xs0

    tagmap = mconcat [ Map.fromSet (const asn1dContent) asn1dTags | ASN1Decode{..} <- xs ]

    anydispatch = case [ asn1dContent | ASN1Decode{..} <- xs, asn1dAny ] of
                    []      -> \tl -> pure (Unexpected tl)
                    [x]     -> x . Just
                    (_:_:_) -> error' "ASN1Decode: CHOICE not possible over multiple ANYs"

    error' :: String -> a
    error' s = error (s ++ " => " ++ show [(asn1dTags x, asn1dAny x, asn1dCard x) | x <- xs ])



-- | Test whether it's a 'mempty' / 'empty' decoder
asn1decodeIsEmpty :: ASN1Decode x -> Bool
asn1decodeIsEmpty ASN1Decode{..} = not asn1dAny && Set.null asn1dTags && asn1dCard == Card 0 0

-- | Test whether decoder ist /monomorphic/. In case of a monomorphic decoder, returns the single tag matched.
asn1decodeIsMono :: ASN1Decode x -> Maybe Tag
asn1decodeIsMono (ASN1Decode {..})
  | asn1dAny                     = Nothing
  | [t1] <- Set.toList asn1dTags = Just t1
  | otherwise                    = Nothing

asn1DecodeSingleton :: Tag -> (TL -> Get x) -> ASN1Decode x
asn1DecodeSingleton t c = asn1DecodeSingleton' t ((Consumed Nothing <$>) . c)

asn1DecodeSingleton' :: Tag -> (TL -> Get (ASN1Res x)) -> ASN1Decode x
asn1DecodeSingleton' t c = empty { asn1dTags    = Set.singleton t
                                 , asn1dCard    = Card 1 0
                                 , asn1dContent = \case
                                     Just tl@(t',_,_) | t /= t' -> pure (Unexpected tl)
                                                      | otherwise -> c tl
                                     Nothing -> pure UnexpectedEOF
                                 }


dec'OPTIONAL :: ASN1Decode x -> ASN1Decode (Maybe x)
dec'OPTIONAL x
  | asn1dCard x /= Card 1 0 = error "OPTIONAL applied to non-singleton"
  | otherwise = x { asn1dCard = Card 0 1
                  , asn1dContent = \case
                      Nothing -> pure $ Consumed Nothing Nothing
                      Just tl -> g <$> asn1dContent x (Just tl)
                  }
  where
    g (Consumed mleftover v) = Consumed mleftover (Just v)
    g (Unexpected leftover)  = Consumed (Just leftover) Nothing
    g UnexpectedEOF          = Consumed Nothing Nothing


instance Functor ASN1Decode where
  fmap f dec = dec { asn1dContent = \tl -> fmap f <$> asn1dContent dec tl }

instance Applicative ASN1Decode where
  pure x = empty { asn1dContent = \tl -> pure (Consumed tl x), asn1dAny = True }
  (<*>) = ap'ASN1Decode
  (*>)  = then'ASN1Decode

ap'ASN1Decode :: ASN1Decode (a -> b) -> ASN1Decode a -> ASN1Decode b
ap'ASN1Decode f x
  = ASN1Decode { asn1dAny  = if fMaySkip then asn1dAny  f || asn1dAny  x else asn1dAny f
               , asn1dTags = if fMaySkip then asn1dTags f <> asn1dTags x else asn1dTags f
               , asn1dCard = asn1dCard f <> asn1dCard x
               , asn1dContent = \mtl -> do
                   res <- getASN1Decode f mtl
                   case res of
                     Consumed (Just tl') f' -> do
                       a' <- getASN1Decode x (Just tl')
                       pure (fmap f' a')
                     Consumed Nothing f' -> do
                       mtl' <- getTagLength BER
                       a' <- getASN1Decode x mtl'
                       pure (fmap f' a')
                     Unexpected (t,_,_) ->
                       fail ("ap'ASN1Decode: Unexpected " ++ show t)
                     UnexpectedEOF ->
                       fail ("ap'ASN1Decode: UnexpectedEOF")
               }
  where
    fMaySkip = cardMaySkip (asn1dCard f)

then'ASN1Decode :: ASN1Decode a -> ASN1Decode b -> ASN1Decode b
then'ASN1Decode f x
  = ASN1Decode { asn1dAny  = if fMaySkip then asn1dAny  f || asn1dAny  x else asn1dAny f
               , asn1dTags = if fMaySkip then asn1dTags f <> asn1dTags x else asn1dTags f
               , asn1dCard = asn1dCard f <> asn1dCard x
               , asn1dContent = \mtl -> do
                   res <- getASN1Decode f mtl
                   case res of
                     Consumed (Just tl') _ -> do
                       getASN1Decode x (Just tl')
                     Consumed Nothing _ -> do
                       mtl' <- getTagLength BER
                       getASN1Decode x mtl'
                     Unexpected (t,_,_) ->
                       fail ("then'ASN1Decode: Unexpected " ++ show t)
                     UnexpectedEOF ->
                       fail ("then'ASN1Decode: UnexpectedEOF")
               }
  where
    fMaySkip = cardMaySkip (asn1dCard f)

asn1fail :: String -> ASN1Decode a
asn1fail s = empty { asn1dAny = True
                   , asn1dContent = \_ -> fail s
                   }

toBinaryGet :: ASN1Decode x -> Get x
toBinaryGet dec
  = getTagLength BER >>= getASN1Decode dec >>= \case
      Unexpected tl -> fail ("ASN1Decode: unexpected " ++ show tl)
      UnexpectedEOF -> fail "ASN1Decode: premature end of stream"
      Consumed (Just tl) _ -> fail ("ASN1Decode: leftover " ++ show tl)
      Consumed Nothing x -> pure x

----------------------------------------------------------------------------
-- simple ASN.1 EDSL

-- bind-like transform
transformVia :: ASN1Decode x -> (x -> Either String y) -> ASN1Decode y
transformVia old f
  = old { asn1dContent = \mtl -> do
            asn1dContent old mtl >>= \case
              Consumed lo x -> case f x of
                                 Left e  -> fail e
                                 Right y -> pure (Consumed lo y)
              Unexpected u  -> pure (Unexpected u)
              UnexpectedEOF -> pure UnexpectedEOF
        }

explicit :: Tag -> ASN1Decode x -> ASN1Decode x
explicit t body = dec'Constructed (show t ++ " EXPLICIT") t body

implicit :: Tag -> ASN1Decode x -> ASN1Decode x
implicit newtag old
  | Just oldtag <- asn1decodeIsMono old
  = empty { asn1dTags    = Set.singleton newtag
          , asn1dCard    = asn1dCard old
          , asn1dContent = \case
              Just tl@(curtag,_,_) | newtag /= curtag -> pure (Unexpected tl)
              Just (_,pc,sz) -> asn1dContent old (Just (oldtag,pc,sz))
              Nothing        -> asn1dContent old Nothing
          }
  | otherwise = error "IMPLICIT applied to non-monomorphic ASN1Decode"

dec'CHOICE :: [ASN1Decode x] -> ASN1Decode x
dec'CHOICE [] = error "CHOICE over no choices"
dec'CHOICE xs = asum'ASN1Decode xs

dec'Constructed :: forall x . String -> Tag -> ASN1Decode x -> ASN1Decode x
dec'Constructed l tag body = asn1DecodeSingleton' tag go
  where
    go :: TL -> Get (ASN1Res x)
    go (_,Primitive,_) = fail (l ++ " with primitive encoding")
    go (_,Constructed,Nothing) = fail (l ++ " with indef length not supported yet")
    go (_,Constructed,Just sz) = isolate64 sz $ do
          tl' <- getTagLength BER
          getASN1Decode body tl'

dec'SEQUENCE :: forall x . ASN1Decode x -> ASN1Decode x
dec'SEQUENCE = dec'Constructed "SEQUENCE" (Universal 16)

dec'SEQUENCE_OF :: forall x . ASN1Decode x -> ASN1Decode [x]
dec'SEQUENCE_OF body = asn1DecodeSingleton' (Universal 16) go
  where
    go :: TL -> Get (ASN1Res [x])
    go (_,Primitive,_)         = fail "SEQUENCE OF with primitive encoding"
    go (_,Constructed,Nothing) = fail "indef SEQUENCE OF not implemented yet"
    go (_,Constructed,Just sz) = isolate64 sz $ do
          -- NB: Get Monad
          let loop :: [x] -> Maybe TL -> Get [x]
              loop acc tl0 = do
                tl' <- case tl0 of
                         Just _  -> pure tl0
                         Nothing -> getTagLength BER
                case tl' of
                  Nothing -> pure (reverse acc)
                  Just _  -> do
                    tmp <- getASN1Decode body tl'
                    case tmp of
                      Consumed tl'' v -> loop (v:acc) tl''
                      UnexpectedEOF   -> fail "dec'SEQUENCE_OF: unexpected EOF"
                      Unexpected t    -> fail ("dec'SEQUENCE_OF: unexpected " ++ show t)

          Consumed Nothing <$> loop [] Nothing


dec'SET_OF :: forall x . ASN1Decode x -> ASN1Decode [x]
dec'SET_OF body = asn1DecodeSingleton' (Universal 17) go
  where
    go :: TL -> Get (ASN1Res [x])
    go (_,Primitive,_)         = fail "SET OF with primitive encoding"
    go (_,Constructed,Nothing) = fail "indef SET OF not implemented yet"
    go (_,Constructed,Just sz) = isolate64 sz $ do
          -- NB: Get Monad
          let loop :: [x] -> Maybe TL -> Get [x]
              loop acc tl0 = do
                tl' <- case tl0 of
                         Just _  -> pure tl0
                         Nothing -> getTagLength BER
                case tl' of
                  Nothing -> pure (reverse acc)
                  Just _  -> do
                    tmp <- getASN1Decode body tl'
                    case tmp of
                      Consumed tl'' v -> loop (v:acc) tl''
                      UnexpectedEOF   -> fail "dec'SET_OF: unexpected EOF"
                      Unexpected t    -> fail ("dec'SET_OF: unexpected " ++ show t)

          Consumed Nothing <$> loop [] Nothing



dec'BOOLEAN :: ASN1Decode Bool
dec'BOOLEAN = asn1DecodeSingleton (Universal 1) $ asPrimitive go
  where
    go 1 = do
      x <- getWord8
      case x of
        0x00 -> pure False
        0xff -> pure True
        _    -> fail "BOOLEAN must be encoded as either 0x00 or 0xFF" -- enforce DER/DER rules here
    go _ = fail "BOOLEAN with content-length not equal 1"

enc'BOOLEAN :: Bool -> ASN1Encode Word64
enc'BOOLEAN v = ASN1Encode $ \mt -> do
  _ <- putTagLength (Universal 1 `fromMaybe` mt, Primitive, Just 1)
  putWord8 (if v then 0xff else 0x00)
  pure 3

{- TODO
getPrim'Boolean :: EncodingRule -> Word64 -> Get Bool
getPrim'Boolean r sz
  | sz /= 1 = fail "boolean content shall be a single octet"
  | otherwise = do
      x <- getWord8
      case (r,x) of
        (_,0x00)   -> pure False
        (BER,_)    -> pure True
        (CER,0xff) -> pure True
        (CER,_)    -> fail "all bits shall be set in boolean TRUE encoding for CER"
        (DER,0xff) -> pure True
        (DER,_)    -> fail "all bits shall be set in boolean TRUE encoding for DER"
-}

dec'INTEGER :: ASN1Decode Integer
dec'INTEGER = asn1DecodeSingleton (Universal 2) $ asPrimitive getVarInteger

enc'INTEGER :: Integer -> ASN1Encode Word64
enc'INTEGER i = wrap'DEFINITE (Universal 2) Primitive (putVarInteger i)

dec'UInt :: forall lb ub t . (UIntBounds lb ub t, Num t) => ASN1Decode (UInt lb ub t)
dec'UInt = transformVia dec'INTEGER $ \i ->
  case uintFromInteger (toInteger i) of
    Left Underflow -> Left "INTEGER below lower bound"
    Left Overflow  -> Left "INTEGER above upper bound"
    Left _         -> Left "INTEGER"
    Right v        -> Right v

enc'UInt :: forall lb ub t . (UIntBounds lb ub t, Num t, Integral t) => UInt lb ub t -> ASN1Encode Word64
enc'UInt = enc'INTEGER . toInteger . fromUInt

dec'Int64 :: ASN1Decode Int64
dec'Int64 = asn1DecodeSingleton (Universal 2) $ asPrimitive getVarInt64

enc'Int64 :: Int64 -> ASN1Encode Word64
enc'Int64 i = wrap'DEFINITE (Universal 2) Primitive (putVarInt64 i)

dec'ENUMERATED :: Enumerated enum => ASN1Decode enum
dec'ENUMERATED = asn1DecodeSingleton (Universal 10) $ asPrimitive $ \sz -> do
    i <- go sz
    maybe (fail "invalid ENUMERATED value") pure (toEnumerated i)
  where
    go 0 = fail "ENUMERATED with empty content"
    go sz
      | sz <= 8   = getVarInt64 sz
      | otherwise = fail "invalid ENUMERATED value"

enc'ENUMERATED :: Enumerated enum => enum -> ASN1Encode Word64
enc'ENUMERATED = retag (Universal 10) . enc'Int64 . fromEnumerated

-- | Only for non-sparse 'Enum's
dec'BoundedEnum :: forall enum . (Bounded enum, Enum enum) => ASN1Decode enum
dec'BoundedEnum = transformVia dec'ENUMERATED $ \i ->
    if (i `inside` (lb,ub))
      then Right (toEnum i)
      else Left "invalid ENUMERATED value"
  where
    lb = fromEnum (minBound :: enum)
    ub = fromEnum (maxBound :: enum)

enc'BoundedEnum :: Enum enum => enum -> ASN1Encode Word64
enc'BoundedEnum v = enc'ENUMERATED (intCast (fromEnum v) :: Int64)

dec'NULL :: ASN1Decode ()
dec'NULL = asn1DecodeSingleton (Universal 5) $ asPrimitive go
  where
    go 0 = pure ()
    go _ = fail "NULL with content-length not equal 0"

enc'NULL :: ASN1Encode Word64
enc'NULL = ASN1Encode $ \mt -> putTagLength (Universal 5 `fromMaybe` mt, Primitive, Just 0)


dec'OCTETSTRING :: ASN1Decode ByteString
dec'OCTETSTRING = asn1DecodeSingleton (Universal 4) $ asPrimitive go
  where
    go sz
      | Just sz' <- intCastMaybe sz = Bin.getByteString sz'
      | otherwise = fail "OCTET STRING too large for this implementation"

enc'OCTETSTRING :: ByteString -> ASN1Encode Word64
enc'OCTETSTRING bs = ASN1Encode $ \mt -> do
  let cl = fromIntegral (BS.length bs)
  hl <- putTagLength (Universal 4 `fromMaybe` mt, Primitive, Just cl)
  Bin.putByteString bs
  pure (hl + cl)

wrap'DEFINITE :: Tag -> TagPC -> PutM Word64 -> ASN1Encode Word64
wrap'DEFINITE t0 pc body = ASN1Encode $ \mt -> do
  let (cl, lbs) = Bin.runPutM body
  hl <- putTagLength (fromMaybe t0 mt, pc, Just cl)
  Bin.putLazyByteString lbs
  pure (hl+cl)


retag :: Tag -> ASN1Encode a -> ASN1Encode a
retag newtag (ASN1Encode old) = ASN1Encode (\mt -> old (mt <|> Just newtag))

wraptag :: Tag -> ASN1Encode Word64 -> ASN1Encode Word64
wraptag newtag (ASN1Encode old) = wrap'DEFINITE newtag Constructed (old Nothing)

----------------------------------------------------------------------------

-- | ASN.1 @IMPLICIT@ Annotation
newtype IMPLICIT (tag :: TagK) x = IMPLICIT x
  deriving (Generic,NFData,IsString,Num,Show,Eq,Ord,Enum)

instance Newtype (IMPLICIT tag x) x

-- | ASN.1 @EXPLICIT@ Annotation
newtype EXPLICIT (tag :: TagK) x = EXPLICIT x
  deriving (Generic,NFData,IsString,Num,Show,Eq,Ord,Enum)

instance Newtype (EXPLICIT tag x) x

-- | ASN.1 @ENUMERATED@ Annotation
newtype ENUMERATED x = ENUMERATED x
  deriving (Generic,NFData,Num,Show,Eq,Ord,Enum)

instance Newtype (ENUMERATED x) x

----------------------------------------------------------------------------

class ASN1 t where
  asn1decode :: ASN1Decode t
  asn1decode = dec'Constructed "SEQUENCE" (asn1defTag (Proxy :: Proxy t)) asn1decodeCompOf

  asn1decodeCompOf :: ASN1Decode t
  asn1decodeCompOf = asn1fail "asn1decodeCompOf not implemented for type"

  asn1encode :: t -> ASN1Encode Word64
  asn1encode = wraptag (asn1defTag (Proxy :: Proxy t)) . asn1encodeCompOf

  -- constructed contents
  asn1encodeCompOf :: t -> ASN1Encode Word64
  asn1encodeCompOf = error "asn1encode(CompOf) not implemented for type"

  -- default-tag
  asn1defTag :: Proxy t -> Tag
  asn1defTag _ = Universal 16

  {-# MINIMAL (asn1decode | asn1decodeCompOf), (asn1encode | asn1encodeCompOf) #-}

instance (ASN1 t1, ASN1 t2) => ASN1 (t1,t2) where
  asn1encodeCompOf (v1,v2) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2]
  asn1decodeCompOf = (,) <$> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3) => ASN1 (t1,t2,t3) where
  asn1encodeCompOf (v1,v2,v3) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3]
  asn1decodeCompOf = (,,) <$> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4) => ASN1 (t1,t2,t3,t4) where
  asn1encodeCompOf (v1,v2,v3,v4) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4]
  asn1decodeCompOf = (,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5) => ASN1 (t1,t2,t3,t4,t5) where
  asn1encodeCompOf (v1,v2,v3,v4,v5) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5]
  asn1decodeCompOf = (,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6) => ASN1 (t1,t2,t3,t4,t5,t6) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6]
  asn1decodeCompOf = (,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7) => ASN1 (t1,t2,t3,t4,t5,t6,t7) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7]
  asn1decodeCompOf = (,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8]
  asn1decodeCompOf = (,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9]
  asn1decodeCompOf = (,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10]
  asn1decodeCompOf = (,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10, ASN1 t11) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10, asn1encode v11]
  asn1decodeCompOf = (,,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10, ASN1 t11, ASN1 t12) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10, asn1encode v11, asn1encode v12]
  asn1decodeCompOf = (,,,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10, ASN1 t11, ASN1 t12, ASN1 t13) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10, asn1encode v11, asn1encode v12, asn1encode v13]
  asn1decodeCompOf = (,,,,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10, ASN1 t11, ASN1 t12, ASN1 t13, ASN1 t14) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10, asn1encode v11, asn1encode v12, asn1encode v13, asn1encode v14]
  asn1decodeCompOf = (,,,,,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

instance (ASN1 t1, ASN1 t2, ASN1 t3, ASN1 t4, ASN1 t5, ASN1 t6, ASN1 t7, ASN1 t8, ASN1 t9, ASN1 t10, ASN1 t11, ASN1 t12, ASN1 t13, ASN1 t14, ASN1 t15) => ASN1 (t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15) where
  asn1encodeCompOf (v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) = enc'SEQUENCE_COMPS [asn1encode v1, asn1encode v2, asn1encode v3, asn1encode v4, asn1encode v5, asn1encode v6, asn1encode v7, asn1encode v8, asn1encode v9, asn1encode v10, asn1encode v11, asn1encode v12, asn1encode v13, asn1encode v14, asn1encode v15]
  asn1decodeCompOf = (,,,,,,,,,,,,,,) <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode



-- | ASN.1 @OCTET STRING@ type
type OCTET_STRING = ByteString

instance ASN1 ByteString where
  asn1defTag _ = Universal 4
  asn1decode = dec'OCTETSTRING
  asn1encode = enc'OCTETSTRING

instance ASN1 SBS.ShortByteString where
  asn1defTag _ = Universal 4
  asn1decode = SBS.toShort <$> dec'OCTETSTRING
  asn1encode = enc'OCTETSTRING . SBS.fromShort -- TODO: optimize

instance ASN1 ShortText where
  asn1defTag _ = Universal 4
  asn1decode = dec'OCTETSTRING `transformVia`
               (maybe (Left "OCTECT STRING contained invalid UTF-8") Right . TS.fromByteString)
  asn1encode = asn1encode . TS.toShortByteString

type BOOLEAN = Bool

instance ASN1 Bool where
  asn1defTag _ = Universal 1
  asn1decode = dec'BOOLEAN
  asn1encode = enc'BOOLEAN

type OPTIONAL x = Maybe x

instance ASN1 t => ASN1 (Maybe t) where
  asn1defTag _ = asn1defTag (Proxy :: Proxy t)
  asn1decode = dec'OPTIONAL asn1decode

  asn1encode Nothing  = empty'ASN1Encode
  asn1encode (Just v) = asn1encode v

instance Enumerated t => ASN1 (ENUMERATED t) where
  asn1defTag _ = Universal 10
  asn1decode = ENUMERATED <$> dec'ENUMERATED
  asn1encode (ENUMERATED v) = enc'ENUMERATED v

instance ASN1 t => ASN1 [t] where
  asn1decode = dec'SEQUENCE_OF asn1decode
  asn1encode = enc'SEQUENCE . map asn1encode

-- | @SEQUENCE SIZE (1..MAX) OF@
instance ASN1 t => ASN1 (NonEmpty t) where
  asn1decode = transformVia asn1decode $ \case
                 []   -> Left "SEQUENCE (1..n) must be non-empty"
                 x:xs -> Right (x :| xs)

  asn1encode (x :| xs) = asn1encode (x:xs)

-- | ASN.1 @SET SIZE (1..MAX) OF@ type
newtype SET1 x = SET1 (NonEmpty x)
  deriving (Generic,NFData,Show,Eq,Ord)

instance Newtype (SET1 x) (NonEmpty x)

instance ASN1 t => ASN1 (SET1 t) where
  asn1defTag _ = Universal 17
  asn1decode = transformVia asn1decode $ \case
                 SET [] -> Left "SET (1..n) must be non-empty"
                 SET (x:xs) -> Right (SET1 (x :| xs))

  asn1encode (SET1 (x :| xs)) = asn1encode (SET (x:xs))

-- | ASN.1 @SET OF@ type
newtype SET x = SET [x]
  deriving (Generic,NFData,Show,Eq,Ord)

instance Newtype (SET x) [x]

instance ASN1 t => ASN1 (SET t) where
  asn1defTag _ = Universal 17
  asn1decode = SET <$> dec'SET_OF asn1decode
  asn1encode (SET vs) = enc'SET (map asn1encode vs)

instance ASN1 Integer where
  asn1defTag _ = Universal 2
  asn1decode = dec'INTEGER
  asn1encode = enc'INTEGER

instance ASN1 Int64 where
  asn1defTag _ = Universal 2
  asn1decode = dec'Int64
  asn1encode = enc'Int64

instance (UIntBounds lb ub t, Integral t) => ASN1 (UInt lb ub t) where
  asn1defTag _ = Universal 2
  asn1decode = dec'UInt
  asn1encode = enc'UInt

instance forall tag t . (KnownTag tag, ASN1 t) => ASN1 (IMPLICIT tag t) where
  asn1defTag _ = tagVal (Proxy :: Proxy tag)
  asn1decode = IMPLICIT <$> implicit (tagVal (Proxy :: Proxy tag)) asn1decode
  asn1encode (IMPLICIT v) = retag (tagVal (Proxy :: Proxy tag)) (asn1encode v)

instance forall tag t . (KnownTag tag, ASN1 t) => ASN1 (EXPLICIT tag t) where
  asn1defTag _ = tagVal (Proxy :: Proxy tag)
  asn1decode = EXPLICIT <$> explicit (tagVal (Proxy :: Proxy tag)) asn1decode
  asn1encode (EXPLICIT v) = wraptag (tagVal (Proxy :: Proxy tag)) (asn1encode v)

-- | ASN.1 @NULL@ type
type NULL = ()

-- | denotes @NULL@
instance ASN1 () where
  asn1defTag _ = Universal 5
  asn1decode = dec'NULL
  asn1encode () = enc'NULL

-- | Helper representing a @BOOLEAN DEFAULT (TRUE|FALSE)@ ASN.1 type annotation
newtype BOOLEAN_DEFAULT (def :: Bool) = BOOLEAN Bool
  deriving (Eq,Ord,Bounded,Enum,Generic,Show,Read,NFData)

instance forall def . KnownBool def => ASN1 (BOOLEAN_DEFAULT def) where
  asn1defTag _ = Universal 1

  asn1encode (BOOLEAN b)
    | b == boolVal (Proxy :: Proxy def) = ASN1Encode $ \_ -> pure 0
    | otherwise                         = asn1encode b

  asn1decode = transformVia (dec'OPTIONAL dec'BOOLEAN) $ \case
      Just True  | defbool     -> Left "encoded TRUE encountered despite 'BOOLEAN DEFAULT TRUE'"
      Just False | not defbool -> Left "encoded FALSE encountered despite 'BOOLEAN DEFAULT FALSE'"
      Just b  -> Right (BOOLEAN b)
      Nothing -> Right (BOOLEAN defbool)
    where
      defbool = boolVal (Proxy :: Proxy def)

class KnownBool (b :: Bool) where boolVal :: Proxy b -> Bool
instance KnownBool 'True where boolVal _ = True
instance KnownBool 'False where boolVal _ = False
