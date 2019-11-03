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

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE Trustworthy                #-}
{-# LANGUAGE TypeOperators              #-}

#if !defined(HS_LDAPv3_ANNOTATED)
{-# OPTIONS_GHC -fno-warn-dodgy-exports #-}
#endif

-- This module is compiled twice; once with ASN.1 type-annotating
-- `newtype` wrappers; and a 2nd time with those newtypes made
-- "transparent" by redefining them as `type` synonyms. The public API
-- exposes the latter version; ASN.1 encoding/decoding goes via the
-- former version.

#if defined(HS_LDAPv3_ANNOTATED)
# define MODULE_NAME LDAPv3.Message.Annotated
#else
# define MODULE_NAME LDAPv3.Message
#endif

-- | This module provides a pure Haskell implementation of the /Lightweight Directory Access Protocol (LDAP)/ version 3 as specified in <https://tools.ietf.org/html/rfc4511 RFC4511>.
--
-- Serializing and deserializing to and from the wire <https://en.wikipedia.org/wiki/ASN.1 ASN.1> encoding is provided via the 'Bin.Binary' instance of 'LDAPMessage'. For the purpose of implementing network clients and servers, the operations
--
-- * 'Bin.encode'
-- * 'Data.Binary.Get.runGetIncremental'
--
-- are most useful.
--
-- When using a streaming I\/O framework such <http://hackage.haskell.org/package/io-streams io-streams> a simple 'Data.Binary.Binary' adapter such as <http://hackage.haskell.org/package/wire-streams wire-streams> makes it easy to implement a LDAPv3 client.
--
-- @since 0.1.0

module MODULE_NAME
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
    , OID(..)
      -- 4.1.3.  Distinguished Name and Relative Distinguished Name
    , LDAPDN
    , RelativeLDAPDN
      -- 4.1.4.  Attribute Descriptions
    , AttributeDescription(..)
    , KeyString
    , Option
      -- 4.1.5.  Attribute Value
    , AttributeValue
      -- 4.1.6.  Attribute Value Assertion
    , AttributeValueAssertion(..)
    , AssertionValue
      -- 4.1.7.  Attribute and PartialAttribute
    , PartialAttribute(..)
    , Attribute(..)
      -- 4.1.8.  Matching Rule Identifier
    , MatchingRuleId(..)
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

    , UnbindRequest

      -- ** Unsolicited Notification  (<https://tools.ietf.org/html/rfc4511#section-4.4 RFC4511 Section 4.4>)
      --
      -- | Unsolicited notifications are represented by an 'ExtendedResponse' message with its 'MessageID' set to @0@.

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

      -- ** Modify Operation   (<https://tools.ietf.org/html/rfc4511#section-4.6 RFC4511 Section 4.6>)

    , ModifyRequest(..)
    , Change(..)
    , Operation(..)
    , ModifyResponse

      -- ** Add Operation   (<https://tools.ietf.org/html/rfc4511#section-4.7 RFC4511 Section 4.7>)

    , AddRequest(..)
    , AttributeList
    , AddResponse

      -- ** Delete Operation   (<https://tools.ietf.org/html/rfc4511#section-4.8 RFC4511 Section 4.8>)

    , DelRequest
    , DelResponse

      -- ** Modify DN Operation   (<https://tools.ietf.org/html/rfc4511#section-4.9 RFC4511 Section 4.9>)

    , ModifyDNRequest(..)
    , ModifyDNResponse

      -- ** Compare Operation   (<https://tools.ietf.org/html/rfc4511#section-4.10 RFC4511 Section 4.10>)

    , CompareRequest(..)
    , CompareResponse

      -- ** Abandon Operation   (<https://tools.ietf.org/html/rfc4511#section-4.11 RFC4511 Section 4.11>)

    , AbandonRequest

      -- ** Extended Operation   (<https://tools.ietf.org/html/rfc4511#section-4.12 RFC4511 Section 4.12>)

    , ExtendedRequest(..)
    , ExtendedResponse(..)

      -- ** Intermediate Response  (<https://tools.ietf.org/html/rfc4511#section-4.13 RFC4511 Section 4.13>)

    , IntermediateResponse(..)

      -- * ASN.1 Helpers
    , NULL
    , OCTET_STRING
    , BOOLEAN_DEFAULT(..)
    , SET(..)
    , SET1(..)
    , COMPONENTS_OF(..)

      -- ** ASN.1 type-level tagging
    , EXPLICIT(..)
    , IMPLICIT(..)
    , ENUMERATED(..)
    , CHOICE(..)
    , TagK(..)

      -- * Unsigned integer sub-type
    , UIntBounds
    , UInt
    , fromUInt
    , toUInt
    ) where

import           Common                      hiding (Option)
import           Data.ASN1.Prim              (TagK (..))
import           Data.Int.Subtypes
import           LDAPv3.AttributeDescription
import           LDAPv3.Message.Types
import           LDAPv3.ResultCode

import qualified Data.Binary                 as Bin

import           Data.ASN1                   (Enumerated, NULL, OCTET_STRING, SET (..), SET1 (..))
#if defined(HS_LDAPv3_ANNOTATED)
import           Data.ASN1                   (ASN1 (..), ASN1Constructed, BOOLEAN_DEFAULT (..), CHOICE (..),
                                              COMPONENTS_OF (..), ENUMERATED (..), EXPLICIT (..),
                                              IMPLICIT (..), gasn1decodeChoice, gasn1encodeChoice,
                                              toBinaryGet, toBinaryPut)
import           Data.ASN1.Prim              (Tag (..))
#else /* defined(HS_LDAPv3_ANNOTATED) */
import qualified LDAPv3.Message.Annotated    as Annotated (LDAPMessage)
import           Unsafe.Coerce               (unsafeCoerce)

-- | ASN.1 @IMPLICIT@ Annotation
type IMPLICIT (tag :: TagK) x = x

-- | ASN.1 @EXPLICIT@ Annotation
type EXPLICIT (tag :: TagK) x = x

-- | ASN.1 @ENUMERATED@ Annotation
type ENUMERATED x = x

-- | Helper representing a @BOOLEAN DEFAULT (TRUE|FALSE)@ ASN.1 type annotation
type BOOLEAN_DEFAULT (def :: Bool) = Bool

-- | ASN.1 @COMPONENTS OF@ Annotation
type COMPONENTS_OF x = x

-- | ASN.1 @CHOICE@ Annotation
type CHOICE x = x

#endif /* defined(HS_LDAPv3_ANNOTATED) */

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
  , _LDAPMessage'protocolOp :: CHOICE ProtocolOp
  , _LDAPMessage'controls   :: Maybe ('CONTEXTUAL 0 `IMPLICIT` Controls)
  } deriving (Generic,Show,Eq)

-- | Encodes to\/from ASN.1 as per <https://tools.ietf.org/html/rfc4511#section-5.1 RFC4511 Section 5.1>
#if defined(HS_LDAPv3_ANNOTATED)
instance Bin.Binary LDAPMessage where
  put = void . toBinaryPut . asn1encode
  get = toBinaryGet asn1decode
#else
instance Bin.Binary LDAPMessage where
  put = Bin.put . (unsafeCoerce :: LDAPMessage -> Annotated.LDAPMessage)
  get = (unsafeCoerce :: Annotated.LDAPMessage -> LDAPMessage) <$> Bin.get
#endif

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 LDAPMessage
instance ASN1Constructed LDAPMessage
#endif

-- | @CHOICE@ type inlined in @LDAPMessage.protocolOp@  (<https://tools.ietf.org/html/rfc4511#section-4.1.1 RFC4511 Section 4.1.1>)
--
data ProtocolOp
  = ProtocolOp'bindRequest     BindRequest
  | ProtocolOp'bindResponse    BindResponse
  | ProtocolOp'unbindRequest   UnbindRequest
  | ProtocolOp'searchRequest   SearchRequest
  | ProtocolOp'searchResEntry  SearchResultEntry
  | ProtocolOp'searchResDone   SearchResultDone
  | ProtocolOp'searchResRef    SearchResultReference
  | ProtocolOp'modifyRequest   ModifyRequest
  | ProtocolOp'modifyResponse  ModifyResponse
  | ProtocolOp'addRequest      AddRequest
  | ProtocolOp'addResponse     AddResponse
  | ProtocolOp'delRequest      DelRequest
  | ProtocolOp'delResponse     DelResponse
  | ProtocolOp'modDNRequest    ModifyDNRequest
  | ProtocolOp'modDNResponse   ModifyDNResponse
  | ProtocolOp'compareRequest  CompareRequest
  | ProtocolOp'compareResponse CompareResponse
  | ProtocolOp'abandonRequest  AbandonRequest
  | ProtocolOp'extendedReq     ExtendedRequest
  | ProtocolOp'extendedResp    ExtendedResponse
  | ProtocolOp'intermediateResponse  IntermediateResponse
  deriving (Generic,Show,Eq)

instance NFData ProtocolOp

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
  , _Control'criticality  :: BOOLEAN_DEFAULT 'False
  , _Control'controlValue :: Maybe OCTET_STRING
  } deriving (Generic,Show,Eq)

instance NFData Control

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 Control
instance ASN1Constructed Control
#endif

{- | Object identifier  (<https://tools.ietf.org/html/rfc4511#section-4.1.2 RFC4511 Section 4.1.2>)

> LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
>                          -- [RFC4512]

-}
type LDAPOID = OID

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
  } deriving (Generic,Show,Eq)

instance NFData BindRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 BindRequest where asn1defTag _ = Application 0
instance ASN1Constructed BindRequest
#endif

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
  deriving (Generic,Show,Eq)

instance NFData AuthenticationChoice

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 AuthenticationChoice where
  asn1decode = gasn1decodeChoice
  asn1encode = gasn1encodeChoice
#endif

{- | See 'AuthenticationChoice'

> SaslCredentials ::= SEQUENCE {
>      mechanism               LDAPString,
>      credentials             OCTET STRING OPTIONAL }

-}
data SaslCredentials = SaslCredentials
  { _SaslCredentials'mechanism   :: LDAPString
  , _SaslCredentials'credentials :: Maybe OCTET_STRING
  } deriving (Generic,Show,Eq)

instance NFData SaslCredentials

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 SaslCredentials
instance ASN1Constructed SaslCredentials
#endif

----------------------------------------------------------------------------

{- | Bind Response  (<https://tools.ietf.org/html/rfc4511#section-4.2 RFC4511 Section 4.2>)

> BindResponse ::= [APPLICATION 1] SEQUENCE {
>      COMPONENTS OF LDAPResult,
>      serverSaslCreds    [7] OCTET STRING OPTIONAL }

-}

data BindResponse = BindResponse
  { _BindResponse'LDAPResult      :: COMPONENTS_OF LDAPResult
  , _BindResponse'serverSaslCreds :: Maybe ('CONTEXTUAL 7 `IMPLICIT` OCTET_STRING)
  } deriving (Generic,Show,Eq)

instance NFData BindResponse

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 BindResponse where asn1defTag _ = Application 1
instance ASN1Constructed BindResponse
#endif

----------------------------------------------------------------------------

{- | Unbind Operation  (<https://tools.ietf.org/html/rfc4511#section-4.3 RFC4511 Section 4.3>)

> UnbindRequest ::= [APPLICATION 2] NULL

-}
type UnbindRequest = ('APPLICATION 2 `IMPLICIT` NULL)

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
  , _SearchRequest'scope        :: ENUMERATED Scope
  , _SearchRequest'derefAliases :: ENUMERATED DerefAliases
  , _SearchRequest'sizeLimit    :: (UInt 0 MaxInt Int32)
  , _SearchRequest'timeLimit    :: (UInt 0 MaxInt Int32)
  , _SearchRequest'typesOnly    :: Bool
  , _SearchRequest'filter       :: Filter
  , _SearchRequest'attributes   :: AttributeSelection
  } deriving (Generic,Show,Eq)

instance NFData SearchRequest

{- | See 'SearchRequest'

> AttributeSelection ::= SEQUENCE OF selector LDAPString
>                -- The LDAPString is constrained to
>                -- <attributeSelector> in Section 4.5.1.8

-}
type AttributeSelection = [LDAPString]

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 SearchRequest where asn1defTag _ = Application 3
instance ASN1Constructed SearchRequest
#endif

-- | See 'SearchRequest'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.2 RFC4511 Section 4.5.1.2>)
data Scope
  = Scope'baseObject
  | Scope'singleLevel
  | Scope'wholeSubtree
  deriving (Generic,Bounded,Enum,Show,Eq)

instance NFData Scope where rnf = rwhnf
instance Enumerated Scope

-- | See 'SearchRequest'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.3 RFC4511 Section 4.5.1.3>)
data DerefAliases
  = DerefAliases'neverDerefAliases
  | DerefAliases'derefInSearching
  | DerefAliases'derefFindingBaseObj
  | DerefAliases'derefAlways
  deriving (Generic,Bounded,Enum,Show,Eq)

instance NFData DerefAliases where rnf = rwhnf
instance Enumerated DerefAliases

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

See also "LDAPv3.StringRepr" for converting 'Filter' to and from the /String Representation of Search Filters/ (<https://tools.ietf.org/html/rfc4515 RFC4515>).

-}
data Filter
  = Filter'and             ('CONTEXTUAL 0 `IMPLICIT` SET1 Filter)
  | Filter'or              ('CONTEXTUAL 1 `IMPLICIT` SET1 Filter)
  | Filter'not             ('CONTEXTUAL 2 `EXPLICIT` Filter)
  | Filter'equalityMatch   ('CONTEXTUAL 3 `IMPLICIT` AttributeValueAssertion)
  | Filter'substrings      ('CONTEXTUAL 4 `IMPLICIT` SubstringFilter)
  | Filter'greaterOrEqual  ('CONTEXTUAL 5 `IMPLICIT` AttributeValueAssertion)
  | Filter'lessOrEqual     ('CONTEXTUAL 6 `IMPLICIT` AttributeValueAssertion)
  | Filter'present         ('CONTEXTUAL 7 `IMPLICIT` AttributeDescription)
  | Filter'approxMatch     ('CONTEXTUAL 8 `IMPLICIT` AttributeValueAssertion)
  | Filter'extensibleMatch ('CONTEXTUAL 9 `IMPLICIT` MatchingRuleAssertion)
  deriving (Generic,Show,Eq)

instance NFData Filter

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 Filter where
  asn1decode = gasn1decodeChoice
  asn1encode = gasn1encodeChoice
#endif

{-  Attribute Descriptions  (<https://tools.ietf.org/html/rfc4511#section-4.1.4 RFC4511 Section 4.1.4>)

> AttributeDescription ::= LDAPString
>                         -- Constrained to <attributedescription>
>                         -- [RFC4512]

@attributedescription@'s syntax is defined in ABNF (<https://tools.ietf.org/search/rfc4234 RFC4234>) notation as

> attributedescription = attributetype options
> attributetype = oid
> options = *( SEMI option )
> option = 1*keychar
> oid = descr / numericoid
> descr = keystring
> numericoid = number 1*( DOT number )
> keystring = leadkeychar *keychar
> leadkeychar = ALPHA
> ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
> keychar = ALPHA / DIGIT / HYPHEN
> number  = DIGIT / ( LDIGIT 1*DIGIT )
> DIGIT   = %x30 / LDIGIT       ; "0"-"9"
> LDIGIT  = %x31-39             ; "1"-"9"
> HYPHEN  = %x2D                ; hyphen ("-")

See also <https://tools.ietf.org/search/rfc4512#section-2.5 RFC4512 Section 2.5> for the definition of @attributedescription@.

-}
-- type AttributeDescription = LDAPString

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
  } deriving (Generic,Show,Eq)

instance NFData AttributeValueAssertion

-- | > AssertionValue ::= OCTET STRING
type AssertionValue = OCTET_STRING

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 AttributeValueAssertion
instance ASN1Constructed AttributeValueAssertion
#endif

{- | Substring 'Filter'  (<https://tools.ietf.org/html/rfc4511#section-4.5.1.7.2 RFC4511 Section 4.5.1.7.2>)

> SubstringFilter ::= SEQUENCE {
>      type           AttributeDescription,
>      substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
>           initial [0] AssertionValue,  -- can occur at most once
>           any     [1] AssertionValue,
>           final   [2] AssertionValue } -- can occur at most once
>      }

__NOTE__: The additional invariants imposed on the ordering and occurence counts of the @initial@ and @final@ entries MUST currently be enforced by the consumer of this library. Future versions of this library might change to enforce these invariants at the type-level.

Specifically, the invariant stated by the specification is:

/There SHALL be at most one @initial@ and at most one @final@ in the @substrings@ of a SubstringFilter.  If @initial@ is present, it SHALL be the first element of @substrings@.  If @final@ is present, it SHALL be the last element of @substrings@./

-}
data SubstringFilter = SubstringFilter
  { _SubstringFilter'type       :: AttributeDescription
  , _SubstringFilter'substrings :: NonEmpty (CHOICE Substring)
  } deriving (Generic,Show,Eq)

instance NFData SubstringFilter

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 SubstringFilter
instance ASN1Constructed SubstringFilter
#endif

-- | See 'SubstringFilter'
data Substring
  = Substring'initial ('CONTEXTUAL 0 `IMPLICIT` AssertionValue) -- ^ may occur at most once; must be first element if present
  | Substring'any     ('CONTEXTUAL 1 `IMPLICIT` AssertionValue)
  | Substring'final   ('CONTEXTUAL 2 `IMPLICIT` AssertionValue) -- ^ may occur at most once; must be last element if present
  deriving (Generic,Show,Eq)

instance NFData Substring

{- | /Extensible Match/ 'SearchRequest' 'Filter' (<https://tools.ietf.org/html/rfc4511#section-4.5.1.7.7 RFC4511 Section 4.5.1.7.7>)

> MatchingRuleAssertion ::= SEQUENCE {
>      matchingRule    [1] MatchingRuleId OPTIONAL,
>      type            [2] AttributeDescription OPTIONAL,
>      matchValue      [3] AssertionValue,
>      dnAttributes    [4] BOOLEAN DEFAULT FALSE }

__NOTE__: The LDAPv3 specification imposes the additional invariant:

/If the @matchingRule@ field is absent, the @type@ field MUST be present/

-}
data MatchingRuleAssertion = MatchingRuleAssertion
  { _MatchingRuleAssertion'matchingRule :: Maybe ('CONTEXTUAL 1 `IMPLICIT` MatchingRuleId)
  , _MatchingRuleAssertion'type         :: Maybe ('CONTEXTUAL 2 `IMPLICIT` AttributeDescription)
  , _MatchingRuleAssertion'matchValue   ::       ('CONTEXTUAL 3 `IMPLICIT` AssertionValue)
  , _MatchingRuleAssertion'dnAttributes ::       ('CONTEXTUAL 4 `IMPLICIT` BOOLEAN_DEFAULT 'False)
  } deriving (Generic,Show,Eq)

instance NFData MatchingRuleAssertion

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 MatchingRuleAssertion
instance ASN1Constructed MatchingRuleAssertion
#endif

----------------------------------------------------------------------------

{- | Search Result Continuation Reference  (<https://tools.ietf.org/html/rfc4511#section-4.5.3 RFC4511 Section 4.5.3>)

> SearchResultReference ::= [APPLICATION 19] SEQUENCE
>                           SIZE (1..MAX) OF uri URI

-}

newtype SearchResultReference = SearchResultReference ('APPLICATION 19 `IMPLICIT` NonEmpty URI)
  deriving (Generic,NFData,Show,Eq)

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 SearchResultReference where
  asn1defTag _ = Application 19 -- not used
  asn1decode = SearchResultReference <$> asn1decode
  asn1encode (SearchResultReference v) = asn1encode v
#endif

----------------------------------------------------------------------------

{- | Search Result Entry  (<https://tools.ietf.org/html/rfc4511#section-4.5.2 RFC4511 Section 4.5.2>)

> SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
>      objectName      LDAPDN,
>      attributes      PartialAttributeList }

-}
data SearchResultEntry = SearchResultEntry
  { _SearchResultEntry'objectName :: LDAPDN
  , _SearchResultEntry'attributes :: PartialAttributeList
  } deriving (Generic,Show,Eq)

instance NFData SearchResultEntry

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 SearchResultEntry where asn1defTag _ = Application 4
instance ASN1Constructed SearchResultEntry
#endif

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
  } deriving (Generic,Show,Eq)

instance NFData PartialAttribute

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 PartialAttribute
instance ASN1Constructed PartialAttribute
#endif


{- | Attribute  (<https://tools.ietf.org/html/rfc4511#section-4.1.7 RFC4511 Section 4.1.7>)

> Attribute ::= PartialAttribute(WITH COMPONENTS {
>      ...,
>      vals (SIZE(1..MAX))})

-}
data Attribute = Attribute
  { _Attribute'type :: AttributeDescription
  , _Attribute'vals :: SET1 AttributeValue
  } deriving (Generic,Show,Eq)

instance NFData Attribute

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 Attribute
instance ASN1Constructed Attribute
#endif

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
  { _LDAPResult'resultCode        :: ENUMERATED ResultCode
  , _LDAPResult'matchedDN         :: LDAPDN
  , _LDAPResult'diagnosticMessage :: LDAPString
  , _LDAPResult'referral          :: Maybe ('CONTEXTUAL 3 `IMPLICIT` Referral)
  } deriving (Generic,Show,Eq)

instance NFData LDAPResult

{- | Referral result code  (<https://tools.ietf.org/html/rfc4511#section-4.1.10 RFC4511 Section 4.1.10>)

> Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

-}
type Referral = ('CONTEXTUAL 3 `IMPLICIT` NonEmpty URI)

{- |

> URI ::= LDAPString     -- limited to characters permitted in
>                        -- URIs

-}
type URI = LDAPString

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 LDAPResult
instance ASN1Constructed LDAPResult
#endif

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

{- | Relative Distinguished Name  (<https://tools.ietf.org/html/rfc4511#section-4.1.3 RFC4511 Section 4.1.3>)

> RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
>                               -- [RFC4514]

-}
type RelativeLDAPDN = LDAPString

{- | Modify Operation  (<https://tools.ietf.org/html/rfc4511#section-4.6 RFC4511 Section 4.6>)

> ModifyRequest ::= [APPLICATION 6] SEQUENCE {
>      object          LDAPDN,
>      changes         SEQUENCE OF change SEQUENCE {
>           operation       ENUMERATED {
>                add     (0),
>                delete  (1),
>                replace (2),
>                ...  },
>           modification    PartialAttribute } }

-}
data ModifyRequest = ModifyRequest
  { _ModifyRequest'object  :: LDAPDN
  , _ModifyRequest'changes :: [Change]
  } deriving (Generic,Show,Eq)

instance NFData ModifyRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 ModifyRequest where asn1defTag _ = Application 6
instance ASN1Constructed ModifyRequest
#endif

-- | See 'ModifyRequest'
data Change = Change
  { _Change'operation    :: ENUMERATED Operation
  , _Change'modification :: PartialAttribute
  } deriving (Generic,Show,Eq)

instance NFData Change

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 Change
instance ASN1Constructed Change
#endif

-- | See 'ModifyRequest' and 'Change'
data Operation
  = Operation'add
  | Operation'delete
  | Operation'replace
  deriving (Generic,Bounded,Enum,Show,Eq)

instance NFData Operation where rnf = rwhnf
instance Enumerated Operation


{- | Modify Response  (<https://tools.ietf.org/html/rfc4511#section-4.6 RFC4511 Section 4.6>)

> ModifyResponse ::= [APPLICATION 7] LDAPResult

-}
type ModifyResponse = ('APPLICATION 7 `IMPLICIT` LDAPResult)

{- | Add Operation  (<https://tools.ietf.org/html/rfc4511#section-4.7 RFC4511 Section 4.7>)

> AddRequest ::= [APPLICATION 8] SEQUENCE {
>      entry           LDAPDN,
>      attributes      AttributeList }

-}
data AddRequest = AddRequest
  { _AddRequest'entry      :: LDAPDN
  , _AddRequest'attributes :: AttributeList
  } deriving (Generic,Show,Eq)

instance NFData AddRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 AddRequest where asn1defTag _ = Application 8
instance ASN1Constructed AddRequest
#endif

{- | Attribute List

> AttributeList ::= SEQUENCE OF attribute Attribute

-}
type AttributeList = [Attribute]

{- | Add Response  (<https://tools.ietf.org/html/rfc4511#section-4.7 RFC4511 Section 4.7>)

> AddResponse ::= [APPLICATION 9] LDAPResult

-}
type AddResponse = ('APPLICATION 9 `IMPLICIT` LDAPResult)


{- | Delete Operation  (<https://tools.ietf.org/html/rfc4511#section-4.8 RFC4511 Section 4.8>)

> DelRequest ::= [APPLICATION 10] LDAPDN

-}
type DelRequest = ('APPLICATION 10 `IMPLICIT` LDAPDN)

{- | Delete Response  (<https://tools.ietf.org/html/rfc4511#section-4.8 RFC4511 Section 4.8>)

> DelResponse ::= [APPLICATION 11] LDAPResult

-}
type DelResponse = ('APPLICATION 11 `IMPLICIT` LDAPResult)

{- | Modify DN Operation  (<https://tools.ietf.org/html/rfc4511#section-4.9 RFC4511 Section 4.9>)

ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
     entry           LDAPDN,
     newrdn          RelativeLDAPDN,
     deleteoldrdn    BOOLEAN,
     newSuperior     [0] LDAPDN OPTIONAL }

-}
data ModifyDNRequest = ModifyDNRequest
  { _ModifyDNRequest'entry        :: LDAPDN
  , _ModifyDNRequest'newrdn       :: RelativeLDAPDN
  , _ModifyDNRequest'deleteoldrdn :: Bool
  , _ModifyDNRequest'newSuperior  :: Maybe ('CONTEXTUAL 0 `IMPLICIT` LDAPDN)
  } deriving (Generic,Show,Eq)

instance NFData ModifyDNRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 ModifyDNRequest where asn1defTag _ = Application 12
instance ASN1Constructed ModifyDNRequest
#endif


{- | Modify DN Response  (<https://tools.ietf.org/html/rfc4511#section-4.9 RFC4511 Section 4.9>)

> ModifyDNResponse ::= [APPLICATION 13] LDAPResult

-}
type ModifyDNResponse = ('APPLICATION 13 `IMPLICIT` LDAPResult)


{- | Compare Operation  (<https://tools.ietf.org/html/rfc4511#section-4.10 RFC4511 Section 4.10>)

> CompareRequest ::= [APPLICATION 14] SEQUENCE {
>      entry           LDAPDN,
>      ava             AttributeValueAssertion }

-}
data CompareRequest = CompareRequest
  { _CompareRequest'entry :: LDAPDN
  , _CompareRequest'ava   :: AttributeValueAssertion
  } deriving (Generic,Show,Eq)

instance NFData CompareRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 CompareRequest where asn1defTag _ = Application 14
instance ASN1Constructed CompareRequest
#endif

{- | Compare Response  (<https://tools.ietf.org/html/rfc4511#section-4.10 RFC4511 Section 4.10>)

> CompareResponse ::= [APPLICATION 15] LDAPResult

-}
type CompareResponse = ('APPLICATION 15 `IMPLICIT` LDAPResult)


{- | Abandon Operation  (<https://tools.ietf.org/html/rfc4511#section-4.11 RFC4511 Section 4.11>)

> AbandonRequest ::= [APPLICATION 16] MessageID

-}
type AbandonRequest = ('APPLICATION 16 `IMPLICIT` MessageID)

{- | Extended Request  (<https://tools.ietf.org/html/rfc4511#section-4.12 RFC4511 Section 4.12>)

> ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
>      requestName      [0] LDAPOID,
>      requestValue     [1] OCTET STRING OPTIONAL }

-}
data ExtendedRequest = ExtendedRequest
  { _ExtendedRequest'responseName  ::       ('CONTEXTUAL 0 `IMPLICIT` LDAPOID)
  , _ExtendedRequest'responseValue :: Maybe ('CONTEXTUAL 1 `IMPLICIT` OCTET_STRING)
  } deriving (Generic,Show,Eq)

instance NFData ExtendedRequest

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 ExtendedRequest where asn1defTag _ = Application 23
instance ASN1Constructed ExtendedRequest
#endif

{- | Extended Response  (<https://tools.ietf.org/html/rfc4511#section-4.12 RFC4511 Section 4.12>)

> ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
>      COMPONENTS OF LDAPResult,
>      responseName     [10] LDAPOID OPTIONAL,
>      responseValue    [11] OCTET STRING OPTIONAL }

-}
data ExtendedResponse = ExtendedResponse
  { _ExtendedResponse'LDAPResult    :: COMPONENTS_OF LDAPResult
  , _ExtendedResponse'responseName  :: Maybe ('CONTEXTUAL 10 `IMPLICIT` LDAPOID)
  , _ExtendedResponse'responseValue :: Maybe ('CONTEXTUAL 11 `IMPLICIT` OCTET_STRING)
  } deriving (Generic,Show,Eq)

instance NFData ExtendedResponse

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 ExtendedResponse where asn1defTag _ = Application 24
instance ASN1Constructed ExtendedResponse
#endif

{- | Intermediate Response  (<https://tools.ietf.org/html/rfc4511#section-4.13 RFC4511 Section 4.13>)

> IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
>         responseName     [0] LDAPOID OPTIONAL,
>         responseValue    [1] OCTET STRING OPTIONAL }

-}
data IntermediateResponse = IntermediateResponse
  { _IntermediateResponse'responseName  :: Maybe ('CONTEXTUAL 0 `IMPLICIT` LDAPOID)
  , _IntermediateResponse'responseValue :: Maybe ('CONTEXTUAL 1 `IMPLICIT` OCTET_STRING)
  } deriving (Generic,Show,Eq)

instance NFData IntermediateResponse

#if defined(HS_LDAPv3_ANNOTATED)
instance ASN1 IntermediateResponse where asn1defTag _ = Application 25
instance ASN1Constructed IntermediateResponse
#endif
