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
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TypeOperators              #-}

-- | This module provides a pure Haskell implementation of the /Lightweight Directory Access Protocol (LDAP)/ version 3.
module LDAPv3
    ( -- * LDAPv3 Protocol data structures
      --
      -- | The Haskell data structures defined in this module closely follow the protocol specification as laid out in <https://tools.ietf.org/html/rfc4511 RFC4511>.
      --
      -- For convenience, the normative <https://en.wikipedia.org/wiki/ASN.1 ASN.1> definitions for each Haskell data type are quoted.

      -- ** Common Elements (<https://tools.ietf.org/html/rfc4511#section-4.1 RFC4511 Section 4.1>)

      -- 4.1.1.  Message Envelope
      LDAPMessage(..)
    , MessageID(..)
    , MaxInt
    , ProtocolOp(..)

      -- 4.1.2.  String Types
    , LDAPString
    , LDAPOID
      -- 4.1.3.  Distinguished Name and Relative Distinguished Name
    , LDAPDN
 -- , RelativeLDAPDN
      -- 4.1.4.  Attribute Descriptions
    , AttributeDescription
      -- 4.1.5.  Attribute Value
    , AttributeValue
      -- 4.1.6.  Attribute Value Assertion
    , AttributeValueAssertion(..)
    , AssertionValue
      -- 4.1.7.  Attribute and PartialAttribute
    , PartialAttribute(..)
 -- , Attribute
      -- 4.1.8.  Matching Rule Identifier
    , MatchingRuleId
      -- 4.1.9.  Result Message
    , LDAPResult(..)
    , ResultCode(..)
      -- 4.1.10.  Referral
    , Referral
    , URI
      -- 4.1.11.  Controls
    , Controls
    , Control(..)

      -- ** Bind Operation  (<https://tools.ietf.org/html/rfc4511#section-4.2 RFC4511 Section 4.2>)

    , BindRequest(..)
    , AuthenticationChoice(..)
    , SaslCredentials(..)
    , BindResponse(..)

      -- ** Unbind Operation  (<https://tools.ietf.org/html/rfc4511#section-4.3 RFC4511 Section 4.3>)

    , UnbindRequest(..)

      -- ** Unsolicited Notification  (<https://tools.ietf.org/html/rfc4511#section-4.4 RFC4511 Section 4.4>)

      -- ** Search Operation  (<https://tools.ietf.org/html/rfc4511#section-4.5 RFC4511 Section 4.5>)

    , SearchRequest(..)
    , Scope(..)
    , DerefAliases(..)
    , AttributeSelection
    , Filter(..)
    , SubstringFilter(..)
    , Substring(..)
    , MatchingRuleAssertion(..)

      -- *** Search Result   (<https://tools.ietf.org/html/rfc4511#section-4.5.2 RFC4511 Section 4.5.2>)

    , SearchResultEntry(..)
    , PartialAttributeList
    , SearchResultReference(..)
    , SearchResultDone

      -- * ASN.1 Helpers
    , OCTET_STRING

      -- ** ASN.1 type-level tagging
    , EXPLICIT(..)
    , IMPLICIT(..)
    , TagK(..)

      -- * Unsigned integer sub-type
    , UIntBounds
    , UInt
    , fromUInt
    , toUInt
    ) where

import           Common
import           Data.ASN1
import           Data.ASN1.Prim
import           Data.Int.Subtypes
import           LDAPv3.ResultCode

import qualified Data.Binary       as Bin

----------------------------------------------------------------------------
-- LDAPv3 protocol

{- | Message Envelope (<https://tools.ietf.org/html/rfc4511#section-4.1.1 RFC4511 Section 4.1.1>)

> LDAPMessage ::= SEQUENCE {
>      messageID       MessageID,
>      protocolOp      CHOICE {
>           bindRequest           BindRequest,
>           bindResponse          BindResponse,
>           unbindRequest         UnbindRequest,
>           searchRequest         SearchRequest,
>           searchResEntry        SearchResultEntry,
>           searchResDone         SearchResultDone,
>           searchResRef          SearchResultReference,
>           modifyRequest         ModifyRequest,
>           modifyResponse        ModifyResponse,
>           addRequest            AddRequest,
>           addResponse           AddResponse,
>           delRequest            DelRequest,
>           delResponse           DelResponse,
>           modDNRequest          ModifyDNRequest,
>           modDNResponse         ModifyDNResponse,
>           compareRequest        CompareRequest,
>           compareResponse       CompareResponse,
>           abandonRequest        AbandonRequest,
>           extendedReq           ExtendedRequest,
>           extendedResp          ExtendedResponse,
>           ...,
>           intermediateResponse  IntermediateResponse },
>      controls       [0] Controls OPTIONAL }

-}
data LDAPMessage = LDAPMessage
  { _LDAPMessage'messageID  :: MessageID
  , _LDAPMessage'protocolOp :: ProtocolOp
  , _LDAPMessage'controls   :: Maybe ('CONTEXTUAL 0 `IMPLICIT` Controls)
  } deriving Show

instance Bin.Binary LDAPMessage where
  put = void . toBinaryPut . asn1encode
  get = toBinaryGet asn1decode

instance ASN1 LDAPMessage where
  asn1decode = with'SEQUENCE $
    LDAPMessage <$> asn1decode <*> asn1decode <*> asn1decode

  asn1encode (LDAPMessage v1 v2 v3)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   , asn1encode v3
                   ]

{- | Message ID (<https://tools.ietf.org/html/rfc4511#section-4.1.1.1 RFC4511 Section 4.1.1.1>)

> MessageID ::= INTEGER (0 ..  maxInt)

-}
newtype MessageID = MessageID (UInt 0 MaxInt Int32)
                  deriving (Show,ASN1)

{- | LDAPv3 protocol ASN.1 constant as per <https://tools.ietf.org/html/rfc4511#section-4.1.1 RFC4511 Section 4.1.1>

> maxInt INTEGER ::= 2147483647 -- (2^^31 - 1)

-}
type MaxInt = 2147483647

-- | @CHOICE@ type inlined in @LDAPMessage.protocolOp@  (<https://tools.ietf.org/html/rfc4511#section-4.1.1 RFC4511 Section 4.1.1>)
--
-- __NOTE__: Not all operations have been implemented yet
data ProtocolOp
  = ProtocolOp'bindRequest     BindRequest
  | ProtocolOp'bindResponse    BindResponse
  | ProtocolOp'unbindRequest   UnbindRequest
  | ProtocolOp'searchRequest   SearchRequest
  | ProtocolOp'searchResEntry  SearchResultEntry
  | ProtocolOp'searchResDone   SearchResultDone
  | ProtocolOp'searchResRef    SearchResultReference
  deriving Show

instance ASN1 ProtocolOp where
  asn1decode = with'CHOICE
    [ ProtocolOp'bindRequest    <$> asn1decode
    , ProtocolOp'bindResponse   <$> asn1decode
    , ProtocolOp'unbindRequest  <$> asn1decode
    , ProtocolOp'searchRequest  <$> asn1decode
    , ProtocolOp'searchResEntry <$> asn1decode
    , ProtocolOp'searchResDone  <$> asn1decode
    , ProtocolOp'searchResRef   <$> asn1decode
    -- TODO
    ]

  asn1encode = \case
    ProtocolOp'bindRequest    v -> asn1encode v
    ProtocolOp'bindResponse   v -> asn1encode v
    ProtocolOp'unbindRequest  v -> asn1encode v
    ProtocolOp'searchRequest  v -> asn1encode v
    ProtocolOp'searchResEntry v -> asn1encode v
    ProtocolOp'searchResDone  v -> asn1encode v
    ProtocolOp'searchResRef   v -> asn1encode v


----------------------------------------------------------------------------

{- | Controls  (<https://tools.ietf.org/html/rfc4511#section-4.1.11 RFC4511 Section 4.1.11>)

> Controls ::= SEQUENCE OF control Control

-}
type Controls = [Control]

{- | Control Entry  (<https://tools.ietf.org/html/rfc4511#section-4.1.11 RFC4511 Section 4.1.11>)

> Control ::= SEQUENCE {
>      controlType             LDAPOID,
>      criticality             BOOLEAN DEFAULT FALSE,
>      controlValue            OCTET STRING OPTIONAL }

-}
data Control = Control
  { _Control'controlType  :: LDAPOID
  , _Control'criticality  :: Maybe Bool -- TODO: actually "DEFAULT FALSE"
  , _Control'controlValue :: Maybe OCTET_STRING
  } deriving Show

instance ASN1 Control where
  asn1decode = with'SEQUENCE $ Control <$> asn1decode <*> asn1decode <*> asn1decode
  asn1encode (Control v1 v2 v3)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   , asn1encode v3
                   ]

{- | Object identifier  (<https://tools.ietf.org/html/rfc4511#section-4.1.2 RFC4511 Section 4.1.2>)

> LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
>                          -- [RFC4512]

-}
type LDAPOID = OCTET_STRING

----------------------------------------------------------------------------

{- | Bind Request  (<https://tools.ietf.org/html/rfc4511#section-4.2 RFC4511 Section 4.2>)

> BindRequest ::= [APPLICATION 0] SEQUENCE {
>      version                 INTEGER (1 ..  127),
>      name                    LDAPDN,
>      authentication          AuthenticationChoice }

-}

data BindRequest = BindRequest
  { bindRequest'version        :: UInt 1 127 Int8
  , bindRequest'name           :: LDAPDN
  , bindRequest'authentication :: AuthenticationChoice
  } deriving Show

instance ASN1 BindRequest where
  asn1decode = implicit (Application 0) $ with'SEQUENCE $
    BindRequest <$> asn1decode <*> asn1decode <*> asn1decode

  asn1encode (BindRequest v1 v2 v3)
    = retag (Application 0) $
      enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   , asn1encode v3
                   ]

----------------------------------------------------------------------------

{- | See 'BindRequest'

> AuthenticationChoice ::= CHOICE {
>      simple                  [0] OCTET STRING,
>                              -- 1 and 2 reserved
>      sasl                    [3] SaslCredentials,
>      ...  }

-}
data AuthenticationChoice
  = AuthenticationChoice'simple  ('CONTEXTUAL 0 `IMPLICIT` OCTET_STRING)
  | AuthenticationChoice'sasl    ('CONTEXTUAL 3 `IMPLICIT` SaslCredentials)
  deriving Show

instance ASN1 AuthenticationChoice where
  asn1decode = with'CHOICE
    [ AuthenticationChoice'simple <$> asn1decode
    , AuthenticationChoice'sasl   <$> asn1decode
    ]

  asn1encode = \case
    AuthenticationChoice'simple v -> asn1encode v
    AuthenticationChoice'sasl   v -> asn1encode v

{- | See 'AuthenticationChoice'

> SaslCredentials ::= SEQUENCE {
>      mechanism               LDAPString,
>      credentials             OCTET STRING OPTIONAL }

-}
data SaslCredentials = SaslCredentials
  { _SaslCredentials'mechanism   :: LDAPString
  , _SaslCredentials'credentials :: Maybe OCTET_STRING
  } deriving Show

instance ASN1 SaslCredentials where
  asn1decode = with'SEQUENCE $ SaslCredentials <$> asn1decode <*> asn1decode

  asn1encode (SaslCredentials v1 v2)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   ]

----------------------------------------------------------------------------

{- | Bind Response  (<https://tools.ietf.org/html/rfc4511#section-4.2 RFC4511 Section 4.2>)

> BindResponse ::= [APPLICATION 1] SEQUENCE {
>      COMPONENTS OF LDAPResult,
>      serverSaslCreds    [7] OCTET STRING OPTIONAL }

-}

data BindResponse = BindResponse
  { _BindResponse'LDAPResult      :: LDAPResult
  , _BindResponse'serverSaslCreds :: Maybe ('CONTEXTUAL 7 `IMPLICIT` OCTET_STRING)
  } deriving Show

instance ASN1 BindResponse where
  asn1decode = implicit (Application 1) $ with'SEQUENCE $ do
    _BindResponse'LDAPResult      <- asn1decodeCompOf
    _BindResponse'serverSaslCreds <- asn1decode
    pure BindResponse{..}

  asn1encode (BindResponse{..})
    = retag (Application 1) $
      enc'SEQUENCE [ asn1encodeCompOf _BindResponse'LDAPResult
                   , asn1encode       _BindResponse'serverSaslCreds
                   ]

----------------------------------------------------------------------------

{- | Unbind Operation  (<https://tools.ietf.org/html/rfc4511#section-4.3 RFC4511 Section 4.3>)

> UnbindRequest ::= [APPLICATION 2] NULL

-}

data UnbindRequest = UnbindRequest
  deriving Show

instance ASN1 UnbindRequest where
  asn1decode = implicit (Application 2) $ (UnbindRequest <$ dec'NULL)
  asn1encode UnbindRequest = retag (Application 2) enc'NULL

----------------------------------------------------------------------------

{- | Search Request  (<https://tools.ietf.org/html/rfc4511#section-4.5.1 RFC4511 Section 4.5.1>)

> SearchRequest ::= [APPLICATION 3] SEQUENCE {
>      baseObject      LDAPDN,
>      scope           ENUMERATED {
>           baseObject              (0),
>           singleLevel             (1),
>           wholeSubtree            (2),
>           ...  },
>      derefAliases    ENUMERATED {
>           neverDerefAliases       (0),
>           derefInSearching        (1),
>           derefFindingBaseObj     (2),
>           derefAlways             (3) },
>      sizeLimit       INTEGER (0 ..  maxInt),
>      timeLimit       INTEGER (0 ..  maxInt),
>      typesOnly       BOOLEAN,
>      filter          Filter,
>      attributes      AttributeSelection }

-}
data SearchRequest = SearchRequest
  { _SearchRequest'baseObject   :: LDAPDN
  , _SearchRequest'scope        :: Scope
  , _SearchRequest'derefAliases :: DerefAliases
  , _SearchRequest'sizeLimit    :: (UInt 0 MaxInt Int32)
  , _SearchRequest'timeLimit    :: (UInt 0 MaxInt Int32)
  , _SearchRequest'typesOnly    :: Bool
  , _SearchRequest'filter       :: Filter
  , _SearchRequest'attributes   :: AttributeSelection
  } deriving Show

{- | See 'SearchRequest'

> AttributeSelection ::= SEQUENCE OF selector LDAPString
>                -- The LDAPString is constrained to
>                -- <attributeSelector> in Section 4.5.1.8

-}
type AttributeSelection = [LDAPString]

instance ASN1 SearchRequest where
  asn1decode = implicit (Application 3) $ with'SEQUENCE $ do
    _SearchRequest'baseObject   <- asn1decode
    _SearchRequest'scope        <- asn1decode
    _SearchRequest'derefAliases <- asn1decode
    _SearchRequest'sizeLimit    <- asn1decode
    _SearchRequest'timeLimit    <- asn1decode
    _SearchRequest'typesOnly    <- asn1decode
    _SearchRequest'filter       <- asn1decode
    _SearchRequest'attributes   <- asn1decode

    pure SearchRequest{..}

  asn1encode (SearchRequest v1 v2 v3 v4 v5 v6 v7 v8)
    = retag (Application 3) $
      enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   , asn1encode v3
                   , asn1encode v4
                   , asn1encode v5
                   , asn1encode v6
                   , asn1encode v7
                   , asn1encode v8
                   ]

-- | See 'SearchRequest'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.2 RFC4511 Section 4.5.1.2>)
data Scope
  = Scope'baseObject
  | Scope'singleLevel
  | Scope'wholeSubtree
  deriving (Bounded,Enum,Show)

instance ASN1 Scope where
  asn1decode = dec'BoundedEnum
  asn1encode = enc'BoundedEnum

-- | See 'SearchRequest'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.3 RFC4511 Section 4.5.1.3>)
data DerefAliases
  = DerefAliases'neverDerefAliases
  | DerefAliases'derefInSearching
  | DerefAliases'derefFindingBaseObj
  | DerefAliases'derefAlways
  deriving (Bounded,Enum,Show)

instance ASN1 DerefAliases where
  asn1decode = dec'BoundedEnum
  asn1encode = enc'BoundedEnum

{- | Search Filter  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.7 RFC4511 Section 4.5.1.7>)

> Filter ::= CHOICE {
>      and             [0] SET SIZE (1..MAX) OF filter Filter,
>      or              [1] SET SIZE (1..MAX) OF filter Filter,
>      not             [2] Filter,
>      equalityMatch   [3] AttributeValueAssertion,
>      substrings      [4] SubstringFilter,
>      greaterOrEqual  [5] AttributeValueAssertion,
>      lessOrEqual     [6] AttributeValueAssertion,
>      present         [7] AttributeDescription,
>      approxMatch     [8] AttributeValueAssertion,
>      extensibleMatch [9] MatchingRuleAssertion,
>      ...  }

-}
data Filter
  = Filter'and             ('CONTEXTUAL 0 `IMPLICIT` SET1 Filter)
  | Filter'or              ('CONTEXTUAL 1 `IMPLICIT` SET1 Filter)
  | Filter'not             ('CONTEXTUAL 2 `EXPLICIT` SET1 Filter)
  | Filter'equalityMatch   ('CONTEXTUAL 3 `IMPLICIT` AttributeValueAssertion)
  | Filter'substrings      ('CONTEXTUAL 4 `IMPLICIT` SubstringFilter)
  | Filter'greaterOrEqual  ('CONTEXTUAL 5 `IMPLICIT` AttributeValueAssertion)
  | Filter'lessOrEqual     ('CONTEXTUAL 6 `IMPLICIT` AttributeValueAssertion)
  | Filter'present         ('CONTEXTUAL 7 `IMPLICIT` AttributeDescription)
  | Filter'approxMatch     ('CONTEXTUAL 8 `IMPLICIT` AttributeValueAssertion)
  | Filter'extensibleMatch ('CONTEXTUAL 9 `IMPLICIT` MatchingRuleAssertion)
  deriving Show

instance ASN1 Filter where
  asn1decode = with'CHOICE
    [ Filter'and             <$> asn1decode
    , Filter'or              <$> asn1decode
    , Filter'not             <$> asn1decode
    , Filter'equalityMatch   <$> asn1decode
    , Filter'substrings      <$> asn1decode
    , Filter'greaterOrEqual  <$> asn1decode
    , Filter'lessOrEqual     <$> asn1decode
    , Filter'present         <$> asn1decode
    , Filter'approxMatch     <$> asn1decode
    , Filter'extensibleMatch <$> asn1decode
    ]

  asn1encode = \case
    Filter'and             v -> asn1encode v
    Filter'or              v -> asn1encode v
    Filter'not             v -> asn1encode v
    Filter'equalityMatch   v -> asn1encode v
    Filter'substrings      v -> asn1encode v
    Filter'greaterOrEqual  v -> asn1encode v
    Filter'lessOrEqual     v -> asn1encode v
    Filter'present         v -> asn1encode v
    Filter'approxMatch     v -> asn1encode v
    Filter'extensibleMatch v -> asn1encode v

{- | Attribute Descriptions  (<https://tools.ietf.org/html/rfc4511#section-4.1.4 RFC4511 Section 4.1.4>)

> AttributeDescription ::= LDAPString
>                         -- Constrained to <attributedescription>
>                         -- [RFC4512]

-}
type AttributeDescription = LDAPString

{- | Attribute Value  (<https://tools.ietf.org/html/rfc4511#section-4.1.5 RFC4511 Section 4.1.5>)

> AttributeValue ::= OCTET STRING

-}
type AttributeValue = OCTET_STRING

{- | Attribute Value Assertion  (<https://tools.ietf.org/html/rfc4511#section-4.1.6 RFC4511 Section 4.1.6>)

> AttributeValueAssertion ::= SEQUENCE {
>      attributeDesc   AttributeDescription,
>      assertionValue  AssertionValue }

-}
data AttributeValueAssertion = AttributeValueAssertion
  { _AttributeValueAssertion'attributeDesc  :: AttributeDescription
  , _AttributeValueAssertion'assertionValue :: AssertionValue
  } deriving Show

-- | > AssertionValue ::= OCTET STRING
type AssertionValue = OCTET_STRING

instance ASN1 AttributeValueAssertion where
  asn1decode = with'SEQUENCE $ AttributeValueAssertion <$> asn1decode <*> asn1decode

  asn1encode (AttributeValueAssertion v1 v2)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   ]

{- | Substring 'Filter'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.7.2 RFC4511 Section 4.5.1.7.2>)

> SubstringFilter ::= SEQUENCE {
>      type           AttributeDescription,
>      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
>           initial [0] AssertionValue,  -- can occur at most once
>           any     [1] AssertionValue,
>           final   [2] AssertionValue } -- can occur at most once
>      }

-}
data SubstringFilter = SubstringFilter
  { _SubstringFilter'type       :: AttributeDescription
  , _SubstringFilter'substrings :: NonEmpty Substring
  } deriving Show

instance ASN1 SubstringFilter where
  asn1decode = with'SEQUENCE $ SubstringFilter <$> asn1decode <*> asn1decode

  asn1encode (SubstringFilter v1 v2)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   ]

-- | See 'SubstringFilter'
data Substring
  = Substring'initial ('CONTEXTUAL 0 `IMPLICIT` AssertionValue)
  | Substring'any     ('CONTEXTUAL 1 `IMPLICIT` AssertionValue)
  | Substring'final   ('CONTEXTUAL 1 `IMPLICIT` AssertionValue)
  deriving Show

instance ASN1 Substring where
  asn1decode = with'CHOICE
    [ Substring'initial <$> asn1decode
    , Substring'any     <$> asn1decode
    , Substring'final   <$> asn1decode
    ]

  asn1encode = \case
    Substring'initial v -> asn1encode v
    Substring'any     v -> asn1encode v
    Substring'final   v -> asn1encode v


{- | Matching Rule Identifier  (<https://tools.ietf.org/html/rfc4511#section-4.1.8 RFC4511 Section 4.1.8>)

> MatchingRuleId ::= LDAPString

-}
type MatchingRuleId = LDAPString

{- | See 'SearchRequest' 'Filter'

> MatchingRuleAssertion ::= SEQUENCE {
>      matchingRule    [1] MatchingRuleId OPTIONAL,
>      type            [2] AttributeDescription OPTIONAL,
>      matchValue      [3] AssertionValue,
>      dnAttributes    [4] BOOLEAN DEFAULT FALSE }

-}
data MatchingRuleAssertion = MatchingRuleAssertion
  { _MatchingRuleAssertion'matchingRule :: Maybe ('CONTEXTUAL 1 `IMPLICIT` MatchingRuleId)
  , _MatchingRuleAssertion'type         :: Maybe ('CONTEXTUAL 2 `IMPLICIT` AttributeDescription)
  , _MatchingRuleAssertion'matchValue   ::       ('CONTEXTUAL 3 `IMPLICIT` AssertionValue)
  , _MatchingRuleAssertion'dnAttributes :: Maybe ('CONTEXTUAL 4 `IMPLICIT` Bool) -- actually DEFAULT FALSE
  } deriving Show

instance ASN1 MatchingRuleAssertion where
  asn1decode = with'SEQUENCE $
    MatchingRuleAssertion <$> asn1decode <*> asn1decode <*> asn1decode <*> asn1decode

  asn1encode (MatchingRuleAssertion v1 v2 v3 v4)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   , asn1encode v3
                   , asn1encode v4
                   ]

----------------------------------------------------------------------------

{- | Search Result Continuation Reference  (<https://tools.ietf.org/html/rfc4511#section-4.5.3 RFC4511 Section 4.5.3>)

> SearchResultReference ::= [APPLICATION 19] SEQUENCE
>                           SIZE (1..MAX) OF uri URI

-}

newtype SearchResultReference = SearchResultReference (NonEmpty URI)
  deriving Show

instance ASN1 SearchResultReference where
  asn1decode = SearchResultReference <$> (Application 19 `implicit` asn1decode)
  asn1encode (SearchResultReference v) = retag (Application 19) $ asn1encode v

----------------------------------------------------------------------------

{- | Search Result Entry  (<https://tools.ietf.org/html/rfc4511#section-4.5.2 RFC4511 Section 4.5.2>)

> SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
>      objectName      LDAPDN,
>      attributes      PartialAttributeList }

-}
data SearchResultEntry = SearchResultEntry
  { _SearchResultEntry'objectName :: LDAPDN
  , _SearchResultEntry'attributes :: PartialAttributeList
  } deriving Show

instance ASN1 SearchResultEntry where
  asn1decode = implicit (Application 4) $ with'SEQUENCE $
    SearchResultEntry <$> asn1decode <*> asn1decode

  asn1encode (SearchResultEntry v1 v2)
    = retag (Application 4) $
      enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   ]

{- | See 'SearchResultEntry'

> PartialAttributeList ::= SEQUENCE OF
>                      partialAttribute PartialAttribute

-}
type PartialAttributeList = [PartialAttribute]

{- | Partial Attribute  (<https://tools.ietf.org/html/rfc4511#section-4.1.7 RFC4511 Section 4.1.7>)

> PartialAttribute ::= SEQUENCE {
>      type       AttributeDescription,
>      vals       SET OF value AttributeValue }

-}
data PartialAttribute = PartialAttribute
  { _PartialAttribute'type :: AttributeDescription
  , _PartialAttribute'vals :: SET AttributeValue
  } deriving Show

instance ASN1 PartialAttribute where
  asn1decode = with'SEQUENCE $ PartialAttribute <$> asn1decode <*> asn1decode
  asn1encode (PartialAttribute v1 v2)
    = enc'SEQUENCE [ asn1encode v1
                   , asn1encode v2
                   ]

----------------------------------------------------------------------------

{- | Search Result Done  (<https://tools.ietf.org/html/rfc4511#section-4.5.2 RFC4511 Section 4.5.2>)

> SearchResultDone ::= [APPLICATION 5] LDAPResult

-}
type SearchResultDone = ('APPLICATION 5 `IMPLICIT` LDAPResult)

----------------------------------------------------------------------------

{- | Result Message  (<https://tools.ietf.org/html/rfc4511#section-4.1.9 RFC4511 Section 4.1.9>)

> LDAPResult ::= SEQUENCE {
>      resultCode         ENUMERATED {
>           success                      (0),
>           operationsError              (1),
>           protocolError                (2),
>           timeLimitExceeded            (3),
>           sizeLimitExceeded            (4),
>           compareFalse                 (5),
>           compareTrue                  (6),
>           authMethodNotSupported       (7),
>           strongerAuthRequired         (8),
>                -- 9 reserved --
>           referral                     (10),
>           adminLimitExceeded           (11),
>           unavailableCriticalExtension (12),
>           confidentialityRequired      (13),
>           saslBindInProgress           (14),
>           noSuchAttribute              (16),
>           undefinedAttributeType       (17),
>           inappropriateMatching        (18),
>           constraintViolation          (19),
>           attributeOrValueExists       (20),
>           invalidAttributeSyntax       (21),
>                -- 22-31 unused --
>           noSuchObject                 (32),
>           aliasProblem                 (33),
>           invalidDNSyntax              (34),
>                -- 35 reserved for undefined isLeaf --
>           aliasDereferencingProblem    (36),
>                -- 37-47 unused --
>           inappropriateAuthentication  (48),
>           invalidCredentials           (49),
>           insufficientAccessRights     (50),
>           busy                         (51),
>           unavailable                  (52),
>           unwillingToPerform           (53),
>           loopDetect                   (54),
>                -- 55-63 unused --
>           namingViolation              (64),
>           objectClassViolation         (65),
>           notAllowedOnNonLeaf          (66),
>           notAllowedOnRDN              (67),
>           entryAlreadyExists           (68),
>           objectClassModsProhibited    (69),
>                -- 70 reserved for CLDAP --
>           affectsMultipleDSAs          (71),
>                -- 72-79 unused --
>           other                        (80),
>           ...  },
>      matchedDN          LDAPDN,
>      diagnosticMessage  LDAPString,
>      referral           [3] Referral OPTIONAL }

-}
data LDAPResult = LDAPResult
  { _LDAPResult'resultCode        :: ResultCode
  , _LDAPResult'matchedDN         :: LDAPDN
  , _LDAPResult'diagnosticMessage :: LDAPString
  , _LDAPResult'referral          :: Maybe ('CONTEXTUAL 3 `IMPLICIT` Referral)
  } deriving Show

{- | Referral result code  (<https://tools.ietf.org/html/rfc4511#section-4.1.10 RFC4511 Section 4.1.10>)

> Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

-}
type Referral = ('CONTEXTUAL 3 `IMPLICIT` NonEmpty URI)

{- |

> URI ::= LDAPString     -- limited to characters permitted in
>                        -- URIs

-}
type URI = LDAPString

instance ASN1 LDAPResult where
  asn1decodeCompOf = do
    _LDAPResult'resultCode        <- asn1decode
    _LDAPResult'matchedDN         <- asn1decode
    _LDAPResult'diagnosticMessage <- asn1decode
    _LDAPResult'referral          <- asn1decode
    pure LDAPResult{..}

  asn1encodeCompOf (LDAPResult v1 v2 v3 v4)
    = enc'SEQUENCE_COMPS [ asn1encode v1
                         , asn1encode v2
                         , asn1encode v3
                         , asn1encode v4
                         ]

{- | String Type  (<https://tools.ietf.org/html/rfc4511#section-4.1.2 RFC4511 Section 4.1.2>)

> LDAPString ::= OCTET STRING -- UTF-8 encoded,
>                             -- [ISO10646] characters

-}
type LDAPString = ShortText

{- | Distinguished Name  (<https://tools.ietf.org/html/rfc4511#section-4.1.3 RFC4511 Section 4.1.3>)

> LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
>                       -- [RFC4514]

-}
type LDAPDN = LDAPString
