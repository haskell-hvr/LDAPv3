module LDAPv3 where

import           Data.ByteString      (ByteString)
import           Data.Int
import           Data.List.NonEmpty   (NonEmpty (..))
import qualified Data.Text.Short      as TS
import           Data.Word

----------------------------------------------------------------------------
-- LDAPv3 protocol

{-
LDAPMessage ::= SEQUENCE {
     messageID       MessageID,
     protocolOp      CHOICE {
          bindRequest           BindRequest,
          bindResponse          BindResponse,
          unbindRequest         UnbindRequest,
          searchRequest         SearchRequest,
          searchResEntry        SearchResultEntry,
          searchResDone         SearchResultDone,
          searchResRef          SearchResultReference,
          modifyRequest         ModifyRequest,
          modifyResponse        ModifyResponse,
          addRequest            AddRequest,
          addResponse           AddResponse,
          delRequest            DelRequest,
          delResponse           DelResponse,
          modDNRequest          ModifyDNRequest,
          modDNResponse         ModifyDNResponse,
          compareRequest        CompareRequest,
          compareResponse       CompareResponse,
          abandonRequest        AbandonRequest,
          extendedReq           ExtendedRequest,
          extendedResp          ExtendedResponse,
          ...,
          intermediateResponse  IntermediateResponse },
     controls       [0] Controls OPTIONAL }
-}

data LDAPMessage = LDAPMessage
  { _LDAPMessage'messageID  :: MessageID
  , _LDAPMessage'protocolOp :: ProtocolOp
  , _LDAPMessage'controls   :: Maybe Controls
  } deriving Show

{-

MessageID ::= INTEGER (0 ..  maxInt)

-}
newtype MessageID = MessageID Int32
                  deriving (Show)

-- @CHOICE@ type inlined in @LDAPMessage.protocolOp@
data ProtocolOp
  = ProtocolOp'bindRequest     BindRequest
  | ProtocolOp'bindResponse    BindResponse
  | ProtocolOp'unbindRequest   UnbindRequest
  | ProtocolOp'searchRequest   SearchRequest
  | ProtocolOp'searchResEntry  SearchResultEntry
  | ProtocolOp'searchResDone   SearchResultDone
  | ProtocolOp'searchResRef    SearchResultReference
  deriving Show

----------------------------------------------------------------------------

{-

Controls ::= SEQUENCE OF control Control

Control ::= SEQUENCE {
     controlType             LDAPOID,
     criticality             BOOLEAN DEFAULT FALSE,
     controlValue            OCTET STRING OPTIONAL }

LDAPOID ::= OCTET STRING -- Constrained to <numericoid> [RFC4512]

-}

type Controls = [Control]

data Control = Control
  { _Control'controlType  :: LDAPOID
  , _Control'criticality  :: Maybe Bool
  , _Control'controlValue :: Maybe OCTET_STRING
  } deriving Show

type LDAPOID = OCTET_STRING

----------------------------------------------------------------------------

{-

BindRequest ::= [APPLICATION 0] SEQUENCE {
     version                 INTEGER (1 ..  127),
     name                    LDAPDN,
     authentication          AuthenticationChoice }

-}

data BindRequest = BindRequest
  { bindRequest'version        :: Int8
  , bindRequest'name           :: LDAPDN
  , bindRequest'authentication :: AuthenticationChoice
  } deriving Show

----------------------------------------------------------------------------

{-

AuthenticationChoice ::= CHOICE {
     simple                  [0] OCTET STRING,
                             -- 1 and 2 reserved
     sasl                    [3] SaslCredentials,
     ...  }

-}

data AuthenticationChoice
  = AuthenticationChoice'simple  OCTET_STRING
  | AuthenticationChoice'sasl    SaslCredentials
  deriving Show

{-

SaslCredentials ::= SEQUENCE {
     mechanism               LDAPString,
     credentials             OCTET STRING OPTIONAL }

-}

data SaslCredentials = SaslCredentials
  { _SaslCredentials'mechanism   :: LDAPString
  , _SaslCredentials'credentials :: Maybe OCTET_STRING
  } deriving Show

----------------------------------------------------------------------------

{-

BindResponse ::= [APPLICATION 1] SEQUENCE {
     COMPONENTS OF LDAPResult,
     serverSaslCreds    [7] OCTET STRING OPTIONAL }

-}

data BindResponse = BindResponse
  { _BindResponse'LDAPResult      :: LDAPResult
  , _BindResponse'serverSaslCreds :: Maybe OCTET_STRING
  } deriving Show

----------------------------------------------------------------------------

{-

UnbindRequest ::= [APPLICATION 2] NULL

-}

data UnbindRequest = UnbindRequest
  deriving Show

----------------------------------------------------------------------------

{-

SearchRequest ::= [APPLICATION 3] SEQUENCE {
     baseObject      LDAPDN,
     scope           ENUMERATED {
          baseObject              (0),
          singleLevel             (1),
          wholeSubtree            (2),
          ...  },
     derefAliases    ENUMERATED {
          neverDerefAliases       (0),
          derefInSearching        (1),
          derefFindingBaseObj     (2),
          derefAlways             (3) },
     sizeLimit       INTEGER (0 ..  maxInt),
     timeLimit       INTEGER (0 ..  maxInt),
     typesOnly       BOOLEAN,
     filter          Filter,
     attributes      AttributeSelection }

AttributeSelection ::= SEQUENCE OF selector LDAPString
               -- The LDAPString is constrained to
               -- <attributeSelector> in Section 4.5.1.8

-}

data SearchRequest = SearchRequest
  { _SearchRequest'baseObject   :: LDAPDN
  , _SearchRequest'scope        :: Scope
  , _SearchRequest'derefAliases :: DerefAliases
  , _SearchRequest'sizeLimit    :: Int32
  , _SearchRequest'timeLimit    :: Int32
  , _SearchRequest'typesOnly    :: Bool
  , _SearchRequest'filter       :: Filter
  , _SearchRequest'attributes   :: AttributeSelection
  } deriving Show

type AttributeSelection = [LDAPString]

data Scope
  = Scope'baseObject
  | Scope'singleLevel
  | Scope'wholeSubtree
  deriving (Bounded,Enum,Show)

data DerefAliases
  = DerefAliases'neverDerefAliases
  | DerefAliases'derefInSearching
  | DerefAliases'derefFindingBaseObj
  | DerefAliases'derefAlways
  deriving (Bounded,Enum,Show)

{-

Filter ::= CHOICE {
     and             [0] SET SIZE (1..MAX) OF filter Filter,
     or              [1] SET SIZE (1..MAX) OF filter Filter,
     not             [2] Filter,
     equalityMatch   [3] AttributeValueAssertion,
     substrings      [4] SubstringFilter,
     greaterOrEqual  [5] AttributeValueAssertion,
     lessOrEqual     [6] AttributeValueAssertion,
     present         [7] AttributeDescription,
     approxMatch     [8] AttributeValueAssertion,
     extensibleMatch [9] MatchingRuleAssertion,
     ...  }


AttributeDescription ::= LDAPString
                        -- Constrained to <attributedescription>
                        -- [RFC4512]

AttributeValue ::= OCTET STRING

AssertionValue ::= OCTET STRING

AttributeValueAssertion ::= SEQUENCE {
     attributeDesc   AttributeDescription,
     assertionValue  AssertionValue }

-}

data Filter
  = Filter'and             [Filter]
  | Filter'or              [Filter]
  | Filter'not             [Filter]
  | Filter'equalityMatch   AttributeValueAssertion
  | Filter'substrings      SubstringFilter
  | Filter'greaterOrEqual  AttributeValueAssertion
  | Filter'lessOrEqual     AttributeValueAssertion
  | Filter'present         AttributeDescription
  | Filter'approxMatch     AttributeValueAssertion
  | Filter'extensibleMatch MatchingRuleAssertion
  deriving Show

type AttributeDescription = LDAPString

type AttributeValue = OCTET_STRING

type AssertionValue = OCTET_STRING

data AttributeValueAssertion = AttributeValueAssertion
  { _AttributeValueAssertion'attributeDesc  :: AttributeDescription
  , _AttributeValueAssertion'assertionValue :: AssertionValue
  } deriving Show

{-

SubstringFilter ::= SEQUENCE {
     type           AttributeDescription,
     substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
          initial [0] AssertionValue,  -- can occur at most once
          any     [1] AssertionValue,
          final   [2] AssertionValue } -- can occur at most once
     }

-}

data SubstringFilter = SubstringFilter
  { _SubstringFilter'type       :: AttributeDescription
  , _SubstringFilter'substrings :: NonEmpty Substring
  } deriving Show

data Substring
  = Substring'initial  AssertionValue
  | Substring'any      AssertionValue
  | Substring'final    AssertionValue
  deriving Show


{-

MatchingRuleAssertion ::= SEQUENCE {
     matchingRule    [1] MatchingRuleId OPTIONAL,
     type            [2] AttributeDescription OPTIONAL,
     matchValue      [3] AssertionValue,
     dnAttributes    [4] BOOLEAN DEFAULT FALSE }

MatchingRuleId ::= LDAPString

-}

type MatchingRuleId = LDAPString

data MatchingRuleAssertion = MatchingRuleAssertion
  { _MatchingRuleAssertion'matchingRule :: Maybe MatchingRuleId
  , _MatchingRuleAssertion'type         :: Maybe AttributeDescription
  , _MatchingRuleAssertion'matchValue   :: AssertionValue
  , _MatchingRuleAssertion'dnAttributes :: Maybe Bool
  } deriving Show

----------------------------------------------------------------------------

{-

SearchResultReference ::= [APPLICATION 19] SEQUENCE
                          SIZE (1..MAX) OF uri URI

-}

newtype SearchResultReference = SearchResultReference (NonEmpty URI)
  deriving Show

----------------------------------------------------------------------------

{-

SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
     objectName      LDAPDN,
     attributes      PartialAttributeList }

PartialAttributeList ::= SEQUENCE OF
                     partialAttribute PartialAttribute

PartialAttribute ::= SEQUENCE {
     type       AttributeDescription,
     vals       SET OF value AttributeValue }

-}

data SearchResultEntry = SearchResultEntry
  { _SearchResultEntry'objectName :: LDAPDN
  , _SearchResultEntry'attributes :: PartialAttributeList
  } deriving Show

type PartialAttributeList = [PartialAttribute]

data PartialAttribute = PartialAttribute
  { _PartialAttribute'type :: AttributeDescription
  , _PartialAttribute'vals :: [AttributeValue]
  } deriving Show

----------------------------------------------------------------------------

{-

SearchResultDone ::= [APPLICATION 5] LDAPResult

-}

type SearchResultDone = LDAPResult

----------------------------------------------------------------------------

{-
LDAPResult ::= SEQUENCE {
     resultCode         ENUMERATED {
          success                      (0),
          operationsError              (1),
          protocolError                (2),
          timeLimitExceeded            (3),
          sizeLimitExceeded            (4),
          compareFalse                 (5),
          compareTrue                  (6),
          authMethodNotSupported       (7),
          strongerAuthRequired         (8),
               -- 9 reserved --
          referral                     (10),
          adminLimitExceeded           (11),
          unavailableCriticalExtension (12),
          confidentialityRequired      (13),
          saslBindInProgress           (14),
          noSuchAttribute              (16),
          undefinedAttributeType       (17),
          inappropriateMatching        (18),
          constraintViolation          (19),
          attributeOrValueExists       (20),
          invalidAttributeSyntax       (21),
               -- 22-31 unused --
          noSuchObject                 (32),
          aliasProblem                 (33),
          invalidDNSyntax              (34),
               -- 35 reserved for undefined isLeaf --
          aliasDereferencingProblem    (36),
               -- 37-47 unused --
          inappropriateAuthentication  (48),
          invalidCredentials           (49),
          insufficientAccessRights     (50),
          busy                         (51),
          unavailable                  (52),
          unwillingToPerform           (53),
          loopDetect                   (54),
               -- 55-63 unused --
          namingViolation              (64),
          objectClassViolation         (65),
          notAllowedOnNonLeaf          (66),
          notAllowedOnRDN              (67),
          entryAlreadyExists           (68),
          objectClassModsProhibited    (69),
               -- 70 reserved for CLDAP --
          affectsMultipleDSAs          (71),
               -- 72-79 unused --
          other                        (80),
          ...  },
     matchedDN          LDAPDN,
     diagnosticMessage  LDAPString,
     referral           [3] Referral OPTIONAL }

Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

URI ::= LDAPString     -- limited to characters permitted in
                       -- URIs

-}

data LDAPResult = LDAPResult
  { _LDAPResult'resultCode        :: ResultCode
  , _LDAPResult'matchedDN         :: LDAPDN
  , _LDAPResult'diagnosticMessage :: LDAPString
  , _LDAPResult'referral          :: Maybe (NonEmpty URI)
  } deriving Show

type URI = LDAPString

newtype ResultCode = ResultCode Word8 deriving (Show,Eq,Ord)

type LDAPString = TS.ShortText -- UTF-8 encoded; [ISO10646] characters

type LDAPDN = LDAPString -- Constrained to <distinguishedName> [RFC4514]

type OCTET_STRING = ByteString
