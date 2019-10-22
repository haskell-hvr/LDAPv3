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

module LDAPv3.ResultCode (ResultCode(..)) where

import           Common
import           Data.ASN1
import qualified Data.Map.Strict as Map
import           Data.Tuple      (swap)

fromEnumeratedMap :: Map.Map ResultCode Int64
fromEnumeratedMap = Map.fromAscList mapping

toEnumeratedMap :: Map.Map Int64 ResultCode
toEnumeratedMap = Map.fromAscList (swap <$> mapping)

mapping :: [(ResultCode,Int64)]
mapping = [ (ResultCode'success                      , 0)
          , (ResultCode'operationsError              , 1)
          , (ResultCode'protocolError                , 2)
          , (ResultCode'timeLimitExceeded            , 3)
          , (ResultCode'sizeLimitExceeded            , 4)
          , (ResultCode'compareFalse                 , 5)
          , (ResultCode'compareTrue                  , 6)
          , (ResultCode'authMethodNotSupported       , 7)
          , (ResultCode'strongerAuthRequired         , 8)
             -- 9 reserved --
          , (ResultCode'referral                     ,10)
          , (ResultCode'adminLimitExceeded           ,11)
          , (ResultCode'unavailableCriticalExtension ,12)
          , (ResultCode'confidentialityRequired      ,13)
          , (ResultCode'saslBindInProgress           ,14)
          , (ResultCode'noSuchAttribute              ,16)
          , (ResultCode'undefinedAttributeType       ,17)
          , (ResultCode'inappropriateMatching        ,18)
          , (ResultCode'constraintViolation          ,19)
          , (ResultCode'attributeOrValueExists       ,20)
          , (ResultCode'invalidAttributeSyntax       ,21)
             -- 22-31 unused --
          , (ResultCode'noSuchObject                 ,32)
          , (ResultCode'aliasProblem                 ,33)
          , (ResultCode'invalidDNSyntax              ,34)
             -- 35 reserved for undefined isLeaf --
          , (ResultCode'aliasDereferencingProblem    ,36)
             -- 37-47 unused --
          , (ResultCode'inappropriateAuthentication  ,48)
          , (ResultCode'invalidCredentials           ,49)
          , (ResultCode'insufficientAccessRights     ,50)
          , (ResultCode'busy                         ,51)
          , (ResultCode'unavailable                  ,52)
          , (ResultCode'unwillingToPerform           ,53)
          , (ResultCode'loopDetect                   ,54)
             -- 55-63 unused --
          , (ResultCode'namingViolation              ,64)
          , (ResultCode'objectClassViolation         ,65)
          , (ResultCode'notAllowedOnNonLeaf          ,66)
          , (ResultCode'notAllowedOnRDN              ,67)
          , (ResultCode'entryAlreadyExists           ,68)
          , (ResultCode'objectClassModsProhibited    ,69)
             -- 70 reserved for CLDAP --
          , (ResultCode'affectsMultipleDSAs          ,71)
             -- 72-79 unused --
          , (ResultCode'other                        ,80)
          ]

-- | 'LDAPv3.LDAPResult' Result Code
data ResultCode
    = ResultCode'success
    | ResultCode'operationsError
    | ResultCode'protocolError
    | ResultCode'timeLimitExceeded
    | ResultCode'sizeLimitExceeded
    | ResultCode'compareFalse
    | ResultCode'compareTrue
    | ResultCode'authMethodNotSupported
    | ResultCode'strongerAuthRequired
      -- 9 reserved --
    | ResultCode'referral
    | ResultCode'adminLimitExceeded
    | ResultCode'unavailableCriticalExtension
    | ResultCode'confidentialityRequired
    | ResultCode'saslBindInProgress
    | ResultCode'noSuchAttribute
    | ResultCode'undefinedAttributeType
    | ResultCode'inappropriateMatching
    | ResultCode'constraintViolation
    | ResultCode'attributeOrValueExists
    | ResultCode'invalidAttributeSyntax
      -- 22-31 unused --
    | ResultCode'noSuchObject
    | ResultCode'aliasProblem
    | ResultCode'invalidDNSyntax
      -- 35 reserved for undefined isLeaf --
    | ResultCode'aliasDereferencingProblem
      -- 37-47 unused --
    | ResultCode'inappropriateAuthentication
    | ResultCode'invalidCredentials
    | ResultCode'insufficientAccessRights
    | ResultCode'busy
    | ResultCode'unavailable
    | ResultCode'unwillingToPerform
    | ResultCode'loopDetect
      -- 55-63 unused --
    | ResultCode'namingViolation
    | ResultCode'objectClassViolation
    | ResultCode'notAllowedOnNonLeaf
    | ResultCode'notAllowedOnRDN
    | ResultCode'entryAlreadyExists
    | ResultCode'objectClassModsProhibited
      -- 70 reserved for CLDAP --
    | ResultCode'affectsMultipleDSAs
      -- 72-79 unused --
    | ResultCode'other
    deriving (Show,Eq,Ord,Bounded,Enum)


instance ASN1 ResultCode where
  asn1decode = (\(ENUMERATED x) -> x) <$> asn1decode
  asn1encode = asn1encode . ENUMERATED

instance Enumerated ResultCode where
  toEnumerated   = Map.lookup `flip` toEnumeratedMap
  fromEnumerated = Map.findWithDefault undefined `flip` fromEnumeratedMap
