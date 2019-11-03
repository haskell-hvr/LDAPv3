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

{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}

module Arbitrary () where

import           LDAPv3.Message

import qualified Data.ByteString           as BS
import qualified Data.Char                 as C
import           Data.Coerce               (coerce)
import           Data.Int
import           Data.List.NonEmpty        (NonEmpty (..))
import           Data.String               (fromString)
import qualified Data.Text.Short           as TS
import           Test.QuickCheck.Instances ()
import           Test.Tasty.QuickCheck

instance Arbitrary TS.ShortText where
  arbitrary = TS.fromText <$> arbitrary
  shrink t = map TS.fromText (shrink (TS.toText t))

-- instance Arbitrary x => Arbitrary (IMPLICIT tag x) where
--   arbitrary = IMPLICIT <$> arbitrary
--   shrink (IMPLICIT x) = coerce (shrink x)

-- instance Arbitrary x => Arbitrary (EXPLICIT tag x) where
--   arbitrary = EXPLICIT <$> arbitrary
--   shrink (EXPLICIT x) = coerce (shrink x)

instance Arbitrary x => Arbitrary (SET x) where
  arbitrary = SET <$> arbitrary
  shrink (SET x) = coerce (shrink x)

instance Arbitrary x => Arbitrary (SET1 x) where
  arbitrary = SET1 <$> arbitrary
  shrink (SET1 x) = coerce (shrink x)

instance Arbitrary MessageID where
  arbitrary = MessageID <$> arbitrary
  shrink (MessageID i) = coerce (shrink i)

instance Arbitrary (UInt 1 127 Int8) where
  arbitrary = either (\_ -> 1) id . toUInt <$> choose (1,127)

instance Arbitrary (UInt 0 MaxInt Int32) where
  arbitrary = int2msgid <$> arbitrary
  shrink = map int2msgid . shrink . fromUInt

int2msgid :: Int32 -> UInt 0 MaxInt Int32
int2msgid = either (\_ -> 0) id . toUInt . abs

instance Arbitrary ResultCode where
  arbitrary = arbitraryBoundedEnum
  shrink ResultCode'success = []
  shrink _                  = [ResultCode'success]

instance Arbitrary LDAPMessage where
  arbitrary = LDAPMessage <$> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

-- instance Arbitrary (BOOLEAN_DEFAULT b) where
--   arbitrary = BOOLEAN <$> arbitrary

instance Arbitrary Control where
  arbitrary = Control <$> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary LDAPResult where
  arbitrary = LDAPResult <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary ProtocolOp where
  arbitrary = frequency
    [ (2, ProtocolOp'bindRequest    <$> arbitrary)
    , (2, ProtocolOp'bindResponse   <$> arbitrary)
    , (1, ProtocolOp'unbindRequest  <$> arbitrary)
    , (5, ProtocolOp'searchRequest  <$> arbitrary)
    , (1, ProtocolOp'searchResDone  <$> arbitrary)
    , (5, ProtocolOp'searchResEntry <$> arbitrary)
    , (2, ProtocolOp'searchResRef   <$> arbitrary)
    , (2, ProtocolOp'modifyRequest  <$> arbitrary)
    , (1, ProtocolOp'modifyResponse <$> arbitrary)
    , (2, ProtocolOp'addRequest     <$> arbitrary)
    , (1, ProtocolOp'addResponse    <$> arbitrary)
    , (1, ProtocolOp'delRequest     <$> arbitrary)
    , (1, ProtocolOp'delResponse    <$> arbitrary)
    , (2, ProtocolOp'modDNRequest   <$> arbitrary)
    , (1, ProtocolOp'modDNResponse  <$> arbitrary)
    , (2, ProtocolOp'compareRequest <$> arbitrary)
    , (1, ProtocolOp'compareResponse <$> arbitrary)
    , (1, ProtocolOp'abandonRequest <$> arbitrary)
    , (2, ProtocolOp'extendedReq    <$> arbitrary)
    , (2, ProtocolOp'extendedResp   <$> arbitrary)
    , (2, ProtocolOp'intermediateResponse <$> arbitrary)
    ]

  shrink = genericShrink

instance Arbitrary BindRequest where
  arbitrary = BindRequest <$> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary AuthenticationChoice where
  arbitrary = oneof [ AuthenticationChoice'simple <$> arbitrary
                    , AuthenticationChoice'sasl <$> arbitrary
                    ]
  shrink = genericShrink

instance Arbitrary SaslCredentials where
  arbitrary = SaslCredentials <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary BindResponse where
  arbitrary = BindResponse <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary SearchRequest where
  arbitrary = SearchRequest <$> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> arbitrary
  shrink = genericShrink

instance Arbitrary Scope where
  arbitrary = arbitraryBoundedEnum
  shrink = genericShrink

instance Arbitrary DerefAliases where
  arbitrary = arbitraryBoundedEnum
  shrink = genericShrink

instance Arbitrary Filter where
  arbitrary = frequency
    [(  1, Filter'and <$> arbitrary)
    ,(  1, Filter'or <$> arbitrary)
    ,(  1, Filter'not <$> arbitrary)
    ,(100, Filter'equalityMatch <$> arbitrary)
    ,(100, Filter'substrings <$> arbitrary)
    ,(100, Filter'greaterOrEqual <$> arbitrary)
    ,(100, Filter'lessOrEqual <$> arbitrary)
    ,(100, Filter'present <$> arbitrary)
    ,(100, Filter'approxMatch <$> arbitrary)
    ,(100, Filter'extensibleMatch <$> arbitrary)
    ]
  shrink = genericShrink

instance Arbitrary SubstringFilter where
  arbitrary = SubstringFilter <$> arbitrary <*> sub'arbitrary
    where
      sub'arbitrary = do
        initial <- oneof [ ((:[]) . Substring'initial) <$> nonEmptyBS, pure [] ]
        final   <- oneof [ ((:[]) . Substring'final)   <$> nonEmptyBS, pure [] ]
        anys    <- case (initial,final) of
                     ([],[]) -> listOf nonEmptyBS `suchThat` (not . null)
                     _       -> listOf nonEmptyBS

        case (initial ++ map Substring'any anys ++ final) of
          []     -> error "the impossible just happened"
          (x:xs) -> pure (x:|xs)

      nonEmptyBS = arbitrary `suchThat` (not . BS.null)
  shrink = genericShrink

instance Arbitrary MatchingRuleAssertion where
  arbitrary = do
    _MatchingRuleAssertion'matchingRule <- arbitrary
    -- /If the @matchingRule@ field is absent, the @type@ field MUST be present/
    _MatchingRuleAssertion'type <- case _MatchingRuleAssertion'matchingRule of
                                     Just _  -> arbitrary
                                     Nothing -> Just <$> arbitrary
    _MatchingRuleAssertion'matchValue <- arbitrary
    _MatchingRuleAssertion'dnAttributes <- arbitrary
    pure MatchingRuleAssertion {..}
  shrink = genericShrink

instance Arbitrary Substring where
  arbitrary = oneof [ Substring'initial <$> nonEmptyBS
                    , Substring'any     <$> nonEmptyBS
                    , Substring'final   <$> nonEmptyBS
                    ]
    where
      nonEmptyBS = arbitrary `suchThat` (not . BS.null)
  -- shrink = genericShrink

instance Arbitrary SearchResultEntry where
  arbitrary = SearchResultEntry <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary PartialAttribute where
  arbitrary = PartialAttribute <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary Attribute where
  arbitrary = Attribute <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary SearchResultReference where
  arbitrary = SearchResultReference <$> arbitrary
  shrink = genericShrink

instance Arbitrary ModifyRequest where
  arbitrary = ModifyRequest <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary Change where
  arbitrary = Change <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary Operation where
  arbitrary = arbitraryBoundedEnum
  shrink = genericShrink

instance Arbitrary AddRequest where
  arbitrary = AddRequest <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary CompareRequest where
  arbitrary = CompareRequest <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary AttributeValueAssertion where
  arbitrary = AttributeValueAssertion <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary ModifyDNRequest where
  arbitrary = ModifyDNRequest <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary ExtendedRequest where
  arbitrary = ExtendedRequest <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary ExtendedResponse where
  arbitrary = ExtendedResponse <$> arbitrary <*> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary IntermediateResponse where
  arbitrary = IntermediateResponse <$> arbitrary <*> arbitrary
  shrink = genericShrink



instance Arbitrary AttributeDescription where
  arbitrary = AttributeDescription <$> arbitrary <*> arbitrary
  shrink = genericShrink

instance Arbitrary MatchingRuleId where
  arbitrary = MatchingRuleId <$> (arbitrary `suchThat` (/= Left "dn")) -- avoid grammar ambiguity
  shrink = genericShrink

instance Arbitrary KeyString where
  arbitrary = fromString <$> ((:) <$> a'leadkeychar <*> listOf a'keychar)

instance Arbitrary Option where
  arbitrary = fromString <$> (listOf a'keychar `suchThat` (not . null))

a'keychar :: Gen Char
a'keychar = choose ('-', 'z') `suchThat` (\c -> C.isAsciiUpper c || C.isAsciiLower c || C.isDigit c || c == '-')

a'leadkeychar :: Gen Char
a'leadkeychar = choose ('A', 'z') `suchThat` C.isLetter

instance Arbitrary OID where
  arbitrary = OID <$> arbitrary
