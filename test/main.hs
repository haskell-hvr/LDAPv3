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

{-# LANGUAGE OverloadedLists     #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main (main) where

import           LDAPv3.Message
import           LDAPv3.StringRepr

import qualified Codec.Base16          as B16
import           Control.DeepSeq
import           Data.Binary           as Bin
import qualified Data.ByteString.Lazy  as BSL
import           Data.Char             (isSpace)
import           Data.Either
import           Data.List.NonEmpty    (NonEmpty (..))
import qualified Data.Text.Short       as TS

import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck as QC

import           Arbitrary             ()

main :: IO ()
main = defaultMain tests

tests, qcPropsRFC4511, qcPropsRFC4515, unitTestsRFC4511, unitTestsRFC4515 :: TestTree

tests = testGroup "Tests" [unitTestsRFC4515, unitTestsRFC4511, qcPropsRFC4515, qcPropsRFC4511]

----------------------------------------------------------------------------------------------------

qcPropsRFC4515 = testGroup "Properties (RFC4515)"
  [ QC.testProperty "parse/render Filter roundtrip" $
      \f -> parseShortText (renderShortText (f :: Filter)) === Just f
  ]

----------------------------------------------------------------------------------------------------

qcPropsRFC4511 = testGroup "Properties (RFC4511)"
  [ QC.testProperty "MessageID round-trip" $
      \msgid -> let msg = LDAPMessage msgid
                                      (ProtocolOp'bindRequest (BindRequest 3 "" (AuthenticationChoice'simple "")))
                                      Nothing
                in decode (encode msg) == msg

  , QC.testProperty "encode" $
      \(msg :: LDAPMessage) -> rnf (encode msg) === ()

  , QC.testProperty "decode . encode == id @LDAPMessage" $
      \(msg :: LDAPMessage) -> (decode . encode) msg === msg

  , QC.testProperty "decode multiple" $
      \msg1 msg2 -> decodeMulti (encode msg1 `mappend` encode msg2) === ([msg1,msg2],mempty)

  , QC.testProperty "decode with noise" $
      \msg1 noise -> decodeOne (encode msg1 `mappend` noise) === Right (msg1,noise)

  , QC.testProperty "decode garbage" $ -- this has a very low probability of the random noise being a valid LDAPMessage
      \noise -> isLeft (decodeOne noise)

  ]
  where
    decodeOne :: BSL.ByteString -> Either BSL.ByteString (LDAPMessage,BSL.ByteString)
    decodeOne raw = case decodeOrFail raw of
      Left (rest,_,_)  -> Left rest
      Right (rest,_,v) -> Right (v,rest)

    decodeMulti :: BSL.ByteString -> ([LDAPMessage],BSL.ByteString)
    decodeMulti = go []
      where
        go acc raw
          | BSL.null raw = (reverse acc, raw)
          | otherwise = case decodeOne raw of
              Left rest      -> (reverse acc, rest)
              Right (v,rest) -> go (v:acc) rest

----------------------------------------------------------------------------------------------------

unitTestsRFC4511 = testGroup "Golden tests (RFC4511)"
  [ testGroup tlabel
    [ testCase "encode" $ Bin.encode ref_msg @?= ref_bin
    , testCase "decode" $ Bin.decode ref_bin @?= ref_msg
    ]

  | (tlabel,ref_bin,ref_msg) <-

    [ ( "bindRequest #1"
      , hex"30 0c 02 01 01 60 07 02 01 03 04 00 80 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 1
                    , _LDAPMessage'protocolOp = ProtocolOp'bindRequest
                        ( BindRequest
                            { bindRequest'version = 3
                            , bindRequest'name = ""
                            , bindRequest'authentication = AuthenticationChoice'simple ""
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "bindRequest #2"
      , hex"30 2b 02 01 01 60 26 02 01 03 04 1a 63 6e 3d 61 64 6d 69 6e 2c 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 80 05 61 64 6d 69 6e"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 1
                    , _LDAPMessage'protocolOp = ProtocolOp'bindRequest
                        ( BindRequest
                            { bindRequest'version = 3
                            , bindRequest'name = "cn=admin,dc=example,dc=org"
                            , bindRequest'authentication = AuthenticationChoice'simple "admin"
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "bindRequest #3"
      , hex"30 18 02 01 02 60 13 02 01 03 04 00 a3 0c 04 0a 44 49 47 45 53 54 2d 4d 44 35"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'bindRequest
                        ( BindRequest
                            { bindRequest'version = 3
                            , bindRequest'name = ""
                            , bindRequest'authentication = AuthenticationChoice'sasl
                                    ( SaslCredentials
                                        { _SaslCredentials'mechanism = "DIGEST-MD5"
                                        , _SaslCredentials'credentials = Nothing
                                        }
                                    )
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "bindResponse #1"
      , hex"30 0c 02 01 01 61 07 0a 01 00 04 00 04 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 1
                    , _LDAPMessage'protocolOp = ProtocolOp'bindResponse
                        ( BindResponse
                            { _BindResponse'LDAPResult = LDAPResult
                                { _LDAPResult'resultCode = ResultCode'success
                                , _LDAPResult'matchedDN = ""
                                , _LDAPResult'diagnosticMessage = ""
                                , _LDAPResult'referral = Nothing
                                }
                            , _BindResponse'serverSaslCreds = Nothing
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "bindResponse #2"
      , hex"30 41 02 01 01 61 3c 0a 01 35 04 00 04 35 75 6e 61 75 74 68 65 6e 74 69 63 61 74 65 64 20 62 69 6e 64 20 28 44 4e 20 77 69 74 68 20 6e 6f 20 70 61 73 73 77 6f 72 64 29 20 64 69 73 61 6c 6c 6f 77 65 64"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 1
                    , _LDAPMessage'protocolOp = ProtocolOp'bindResponse
                        ( BindResponse
                            { _BindResponse'LDAPResult = LDAPResult
                                { _LDAPResult'resultCode = ResultCode'unwillingToPerform
                                , _LDAPResult'matchedDN = ""
                                , _LDAPResult'diagnosticMessage = "unauthenticated bind (DN with no password) disallowed"
                                , _LDAPResult'referral = Nothing
                                }
                            , _BindResponse'serverSaslCreds = Nothing
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "bindResponse #3"
      , hex"30 0c 02 01 01 61 07 0a 01 31 04 00 04 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 1
                    , _LDAPMessage'protocolOp = ProtocolOp'bindResponse
                        ( BindResponse
                            { _BindResponse'LDAPResult = LDAPResult
                                { _LDAPResult'resultCode = ResultCode'invalidCredentials
                                , _LDAPResult'matchedDN = ""
                                , _LDAPResult'diagnosticMessage = ""
                                , _LDAPResult'referral = Nothing
                                }
                            , _BindResponse'serverSaslCreds = Nothing
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )


    , ( "searchRequest #1"
      , hex"30 36 02 01 02 63 31 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 0a 01 02 0a 01 00 02 01 00 02 01 00 01 01 00 87 0b 6f 62 6a 65 63 74 63 6c 61 73 73 30 00"

      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchRequest
                        ( SearchRequest
                            { _SearchRequest'baseObject = "dc=example,dc=org"
                            , _SearchRequest'scope = Scope'wholeSubtree
                            , _SearchRequest'derefAliases = DerefAliases'neverDerefAliases
                            , _SearchRequest'sizeLimit = 0
                            , _SearchRequest'timeLimit = 0
                            , _SearchRequest'typesOnly = False
                            , _SearchRequest'filter = Filter'present "objectclass"
                            , _SearchRequest'attributes = []
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchRequest #2"
      , hex"30 42 02 01 02 63 3d 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 0a 01 02 0a 01 00 02 01 00 02 01 00 01 01 00 a2 17 a3 15 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73 04 06 70 65 72 73 6f 6e 30 00"

      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchRequest
                        ( SearchRequest
                            { _SearchRequest'baseObject = "dc=example,dc=org"
                            , _SearchRequest'scope = Scope'wholeSubtree
                            , _SearchRequest'derefAliases = DerefAliases'neverDerefAliases
                            , _SearchRequest'sizeLimit = 0
                            , _SearchRequest'timeLimit = 0
                            , _SearchRequest'typesOnly = False
                            , _SearchRequest'filter = Filter'not
                                    ( Filter'equalityMatch
                                            ( AttributeValueAssertion
                                                { _AttributeValueAssertion'attributeDesc = "objectClass"
                                                , _AttributeValueAssertion'assertionValue = "person"
                                                }
                                            )
                                    )
                            , _SearchRequest'attributes = []
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchRequest #3"
      , hex"30 81 80 02 01 02 63 7b 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 0a 01 02 0a 01 00 02 01 00 02 01 00 01 01 00 a0 55 a2 3c a1 3a a9 1f 82 02 6f 75 83 16 52 65 73 65 61 72 63 68 41 6e 64 44 65 76 65 6c 6f 70 6d 65 6e 74 84 01 ff a9 17 82 02 6f 75 83 0e 48 75 6d 61 6e 52 65 73 6f 75 72 63 65 73 84 01 ff a3 15 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73 04 06 70 65 72 73 6f 6e 30 00"

      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchRequest
                        ( SearchRequest
                            { _SearchRequest'baseObject = "dc=example,dc=org"
                            , _SearchRequest'scope = Scope'wholeSubtree
                            , _SearchRequest'derefAliases = DerefAliases'neverDerefAliases
                            , _SearchRequest'sizeLimit = 0
                            , _SearchRequest'timeLimit = 0
                            , _SearchRequest'typesOnly = False
                            , _SearchRequest'filter = Filter'and
                                    ( SET1
                                        ( Filter'not
                                                ( Filter'or
                                                        ( SET1
                                                            ( Filter'extensibleMatch
                                                                    ( MatchingRuleAssertion
                                                                        { _MatchingRuleAssertion'matchingRule = Nothing
                                                                        , _MatchingRuleAssertion'type = Just "ou"
                                                                        , _MatchingRuleAssertion'matchValue = "ResearchAndDevelopment"
                                                                        , _MatchingRuleAssertion'dnAttributes = True
                                                                        }
                                                                    )
                                                                :|
                                                                [ Filter'extensibleMatch
                                                                        ( MatchingRuleAssertion
                                                                            { _MatchingRuleAssertion'matchingRule = Nothing
                                                                            , _MatchingRuleAssertion'type = Just "ou"
                                                                            , _MatchingRuleAssertion'matchValue = "HumanResources"
                                                                            , _MatchingRuleAssertion'dnAttributes = True
                                                                            }
                                                                        )
                                                                ]
                                                            )
                                                        )
                                                )
                                            :|
                                            [ Filter'equalityMatch
                                                    ( AttributeValueAssertion
                                                        { _AttributeValueAssertion'attributeDesc = "objectClass"
                                                        , _AttributeValueAssertion'assertionValue = "person"
                                                        }
                                                    )
                                            ]
                                        )
                                    )
                            , _SearchRequest'attributes = []
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }


      )

    , ( "searchRequest #4"
      , hex"30 3a 02 01 02 63 35 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 0a 01 02 0a 01 00 02 01 00 02 01 00 01 01 00 a4 0f 04 02 63 6e 30 09 80 01 61 81 01 6d 82 01 6e 30 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchRequest
                        ( SearchRequest
                            { _SearchRequest'baseObject = "dc=example,dc=org"
                            , _SearchRequest'scope = Scope'wholeSubtree
                            , _SearchRequest'derefAliases = DerefAliases'neverDerefAliases
                            , _SearchRequest'sizeLimit = 0
                            , _SearchRequest'timeLimit = 0
                            , _SearchRequest'typesOnly = False
                            , _SearchRequest'filter = Filter'substrings
                                    ( SubstringFilter
                                        { _SubstringFilter'type = "cn"
                                        , _SubstringFilter'substrings =
                                            [ Substring'initial "a"
                                            , Substring'any "m"
                                            , Substring'final "n"
                                            ]
                                        }
                                    )
                            , _SearchRequest'attributes = []
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchResEntry #1"
      , hex"30 6e 02 01 02 64 69 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 30 54 30 2c 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73 31 1d 04 03 74 6f 70 04 08 64 63 4f 62 6a 65 63 74 04 0c 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 30 13 04 01 6f 31 0e 04 0c 45 78 61 6d 70 6c 65 20 49 6e 63 2e 30 0f 04 02 64 63 31 09 04 07 65 78 61 6d 70 6c 65"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchResEntry
                        ( SearchResultEntry
                            { _SearchResultEntry'objectName = "dc=example,dc=org"
                            , _SearchResultEntry'attributes =
                                [ PartialAttribute
                                    { _PartialAttribute'type = "objectClass"
                                    , _PartialAttribute'vals = SET
                                        [ "top"
                                        , "dcObject"
                                        , "organization"
                                        ]
                                    }
                                , PartialAttribute
                                    { _PartialAttribute'type = "o"
                                    , _PartialAttribute'vals = SET [ "Example Inc." ]
                                    }
                                , PartialAttribute
                                    { _PartialAttribute'type = "dc"
                                    , _PartialAttribute'vals = SET [ "example" ]
                                    }
                                ]
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchResEntry #2"
      , hex"30 81 ce 02 01 02 64 81 c8 04 1a 63 6e 3d 61 64 6d 69 6e 2c 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67 30 81 a9 30 39 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73 31 2a 04 14 73 69 6d 70 6c 65 53 65 63 75 72 69 74 79 4f 62 6a 65 63 74 04 12 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 61 6c 52 6f 6c 65 30 0d 04 02 63 6e 31 07 04 05 61 64 6d 69 6e 30 23 04 0b 64 65 73 63 72 69 70 74 69 6f 6e 31 14 04 12 4c 44 41 50 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 30 38 04 0c 75 73 65 72 50 61 73 73 77 6f 72 64 31 28 04 26 7b 53 53 48 41 7d 54 66 50 53 6f 37 46 68 58 38 63 34 53 6b 6c 4f 52 58 75 46 54 55 75 67 39 38 64 4e 46 4c 6b 34"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchResEntry
                        ( SearchResultEntry
                            { _SearchResultEntry'objectName = "cn=admin,dc=example,dc=org"
                            , _SearchResultEntry'attributes =
                                [ PartialAttribute
                                    { _PartialAttribute'type = "objectClass"
                                    , _PartialAttribute'vals = SET
                                        [ "simpleSecurityObject"
                                        , "organizationalRole"
                                        ]
                                    }
                                , PartialAttribute
                                    { _PartialAttribute'type = "cn"
                                    , _PartialAttribute'vals = SET [ "admin" ]
                                    }
                                , PartialAttribute
                                    { _PartialAttribute'type = "description"
                                    , _PartialAttribute'vals = SET [ "LDAP administrator" ]
                                    }
                                , PartialAttribute
                                    { _PartialAttribute'type = "userPassword"
                                    , _PartialAttribute'vals = SET [ "{SSHA}TfPSo7FhX8c4SklORXuFTUug98dNFLk4" ]
                                    }
                                ]
                            }
                        )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchResDone #1"
      , hex"30 0c 02 01 02 65 07 0a 01 00 04 00 04 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchResDone
                            ( LDAPResult
                                { _LDAPResult'resultCode = ResultCode'success
                                , _LDAPResult'matchedDN = ""
                                , _LDAPResult'diagnosticMessage = ""
                                , _LDAPResult'referral = Nothing
                                }
                            )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "searchResDone #2"
      , hex"30 0c 02 01 02 65 07 0a 01 20 04 00 04 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 2
                    , _LDAPMessage'protocolOp = ProtocolOp'searchResDone
                            ( LDAPResult
                                { _LDAPResult'resultCode = ResultCode'noSuchObject
                                , _LDAPResult'matchedDN = ""
                                , _LDAPResult'diagnosticMessage = ""
                                , _LDAPResult'referral = Nothing
                                }
                            )
                    , _LDAPMessage'controls = Nothing
                    }
      )

    , ( "unbindRequest"
      , hex"30 05 02 01 03 42 00"
      , LDAPMessage { _LDAPMessage'messageID = MessageID 3
                    , _LDAPMessage'protocolOp = ProtocolOp'unbindRequest ()
                    , _LDAPMessage'controls = Nothing
                    }
      )

    ]

  ]

----------------------------------------------------------------------------------------------------

unitTestsRFC4515 = testGroup "Golden tests (RFC4515)"
  [ testGroup tlabel $
    [ testCase "parseFilter"  $ parseShortText ref_string  @?= Just ref_filter
    , testCase "renderFilter" $ renderShortText ref_filter @?= ref_string2
    ] ++
    [ testCase "parseFilter #2"  $ parseShortText ref_string2 @?= Just ref_filter
    | ref_string2 /= ref_string
    ]

  | (tlabel,(ref_string,ref_string2),ref_filter) <-
    [
        ( "RFC4515 example #1"
        , dup"(cn=Babs Jensen)"
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "cn"
                , _AttributeValueAssertion'assertionValue = "Babs Jensen"
                }
            )
        )
    ,
        ( "RFC4515 example #2"
        , dup"(!(cn=Tim Howes))"
        , Filter'not
            ( Filter'equalityMatch
                ( AttributeValueAssertion
                    { _AttributeValueAssertion'attributeDesc = "cn"
                    , _AttributeValueAssertion'assertionValue = "Tim Howes"
                    }
                )
            )
        )
    ,
        ( "RFC4515 example #3"
        , dup"(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))"
        , Filter'and
            ( SET1
                ( Filter'equalityMatch
                    ( AttributeValueAssertion
                        { _AttributeValueAssertion'attributeDesc = "objectClass"
                        , _AttributeValueAssertion'assertionValue = "Person"
                        }
                    ) :|
                    [ Filter'or
                        ( SET1
                            ( Filter'equalityMatch
                                ( AttributeValueAssertion
                                    { _AttributeValueAssertion'attributeDesc = "sn"
                                    , _AttributeValueAssertion'assertionValue = "Jensen"
                                    }
                                ) :|
                                [ Filter'substrings
                                    ( SubstringFilter
                                        { _SubstringFilter'type = "cn"
                                        , _SubstringFilter'substrings = Substring'initial "Babs J" :| []
                                        }
                                    )
                                ]
                            )
                        )
                    ]
                )
            )
        )
    ,
        ( "RFC4515 example #4"
        , dup"(o=univ*of*mich*)"
        , Filter'substrings
            ( SubstringFilter
                { _SubstringFilter'type = "o"
                , _SubstringFilter'substrings = Substring'initial "univ" :|
                    [ Substring'any "of"
                    , Substring'any "mich"
                    ]
                }
            )
        )
    ,
        ( "RFC4515 example #5"
        , dup"(seeAlso=)"
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "seeAlso"
                , _AttributeValueAssertion'assertionValue = ""
                }
            )
        )
    ,
        ( "RFC4515 example #6"
        , dup"(cn:caseExactMatch:=Fred Flintstone)"
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Just "caseExactMatch"
                , _MatchingRuleAssertion'type = Just "cn"
                , _MatchingRuleAssertion'matchValue = "Fred Flintstone"
                , _MatchingRuleAssertion'dnAttributes = False
                }
            )
        )
    ,
        ( "RFC4515 example #7"
        , dup"(cn:=Betty Rubble)"
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Nothing
                , _MatchingRuleAssertion'type = Just "cn"
                , _MatchingRuleAssertion'matchValue = "Betty Rubble"
                , _MatchingRuleAssertion'dnAttributes = False
                }
            )
        )
    ,
        ( "RFC4515 example #8"
        , dup"(sn:dn:2.4.6.8.10:=Barney Rubble)"
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Just "2.4.6.8.10"
                , _MatchingRuleAssertion'type = Just "sn"
                , _MatchingRuleAssertion'matchValue = "Barney Rubble"
                , _MatchingRuleAssertion'dnAttributes = True
                }
            )
        )
    ,
        ( "RFC4515 example #9"
        , dup"(o:dn:=Ace Industry)"
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Nothing
                , _MatchingRuleAssertion'type = Just "o"
                , _MatchingRuleAssertion'matchValue = "Ace Industry"
                , _MatchingRuleAssertion'dnAttributes = True
                }
            )
        )
    ,
        ( "RFC4515 example #10"
        , dup"(:1.2.3:=Wilma Flintstone)"
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Just "1.2.3"
                , _MatchingRuleAssertion'type = Nothing
                , _MatchingRuleAssertion'matchValue = "Wilma Flintstone"
                , _MatchingRuleAssertion'dnAttributes = False
                }
            )
        )
    ,
        ( "RFC4515 example #11"
        , ( "(:DN:2.4.6.8.10:=Dino)"
          , "(:dn:2.4.6.8.10:=Dino)"
          )
        , Filter'extensibleMatch
            ( MatchingRuleAssertion
                { _MatchingRuleAssertion'matchingRule = Just "2.4.6.8.10"
                , _MatchingRuleAssertion'type = Nothing
                , _MatchingRuleAssertion'matchValue = "Dino"
                , _MatchingRuleAssertion'dnAttributes = True
                }
            )
        )
    ,
        ( "RFC4515 example #12"
        , dup"(o=Parens R Us \\28for all your parenthetical needs\\29)"
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "o"
                , _AttributeValueAssertion'assertionValue = "Parens R Us (for all your parenthetical needs)"
                }
            )
        )
    ,
        ( "RFC4515 example #13"
        , ( "(cn=*\\2A*)"
          , "(cn=*\\2a*)"
          )
        , Filter'substrings
            ( SubstringFilter
                { _SubstringFilter'type = "cn"
                , _SubstringFilter'substrings = Substring'any "*" :| []
                }
            )
        )
    ,
        ( "RFC4515 example #14"
        , dup"(filename=C:\\5cMyFile)"
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "filename"
                , _AttributeValueAssertion'assertionValue = "C:\\MyFile"
                }
            )
        )
    ,
        ( "RFC4515 example #15"
        , ( "(bin=\\00\\00\\00\\04)"
          , "(bin=\\00\\00\\00\x04)"
          )
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "bin"
                , _AttributeValueAssertion'assertionValue = "\x0\x0\x0\x4"
                }
            )
        )
    ,
        ( "RFC4515 example #16"
        , ( "(sn=Lu\\c4\\8di\\c4\\87)"
          , "(sn=Lučić)"
          )
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "sn"
                , _AttributeValueAssertion'assertionValue = "LuÄ\x8diÄ\x87" -- Lučić
                }
            )
        )
    ,
        ( "RFC4515 example #17"
        , ( "(1.3.6.1.4.1.1466.0=\\04\\02\\48\\69)"
          , "(1.3.6.1.4.1.1466.0=\x04\x02Hi)"
          )
        , Filter'equalityMatch
            ( AttributeValueAssertion
                { _AttributeValueAssertion'attributeDesc = "1.3.6.1.4.1.1466.0"
                , _AttributeValueAssertion'assertionValue = "\x04\x02\x48\x69" -- ASN.1 encoding
                }
            )
        )
    ]
  ]

----------------------------------------------------------------------------------------------------
-- local helper

dup :: x -> (x,x)
dup x = (x,x)

hex :: TS.ShortText -> BSL.ByteString
hex = either error id . B16.decode . TS.toShortByteString . TS.filter (not . isSpace)
