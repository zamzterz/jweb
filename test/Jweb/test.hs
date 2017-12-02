{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}

import Test.Hspec
import Test.Hspec.Wai
import Test.Hspec.Wai.JSON
import Test.Tasty
import Test.Tasty.Hspec
import Test.Tasty.HUnit
import Test.Tasty.Program

import qualified Data.ByteString.Char8 as C
import qualified Data.ByteString.Lazy.Char8 as L

import Jose.Jwk
import Jose.Jwt
import Jweb.Encrypt
import Jweb.Decrypt

import Jweb.App (waiApp)

import Network.HTTP.Types.URI (urlEncode)

main = do
    apiTests <- restTests
    defaultMain (testGroup "Tests" [jwebUnitTests, cliTests, apiTests])

testJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.Gl_JYiuaDbTiASvXoxdAU2srn9bolXBEd7h5eagCbwx1hxBWi-SLkKf34sgg0DIBwJ7DxNSDgtOrFcNxLWcy1w.3mfMQb0YVn_cmCdv.e2G1sA.sQkBo1l32d3Xunw9VNPK9A"
testData = "test"

jwebUnitTests = testGroup "Jweb lib: unit tests"
    [ testCaseSteps "Should be able to encrypt and decrypt data with RSA key" $ \step -> do
        let testData = "test_data"
        publicKeyData <- readFile "test/key1.pub"
        privateKeyData <- readFile "test/key1.priv"

        step "Encrypting"
        Right (Jwt encrypted) <- encrypt publicKeyData (C.pack testData)

        step "Decrypting"
        Right (Jwe (hdr, claims)) <- decrypt privateKeyData encrypted

        step "Asserting"
        testData @=? C.unpack claims

    , testCaseSteps "Should reject decryption with wrong key" $ \step -> do
        publicKeyData <- readFile "test/key1.pub"
        otherPrivateKeyData <- readFile "test/key2.priv"

        step "Encrypting with key1.pub"
        Right (Jwt encrypted) <- encrypt publicKeyData (C.pack "test_data")

        step "Decrypting with key2.priv"
        decrypted <- decrypt otherPrivateKeyData encrypted
        Left (BadCrypto) @=? decrypted

    , testCase "Should reject bad key for encryption with Left error" $ do
        privateKeyData <- readFile "test/key1.priv" -- can't use private key for encryption
        encrypted <- encrypt privateKeyData (C.pack "test_data")
        case encrypted of
            Right a -> assertFailure "Expected a KeyError"
            Left (KeyError msg) -> return () -- do nothing
            _ -> assertFailure "Expected a KeyError"

    , testCase "Should reject bad key for decryption with Left error" $ do
        publicKeyData <- readFile "test/key1.pub" -- can't use public key for decryption
        decrypted <- decrypt publicKeyData (C.pack testJwe)
        case decrypted of
            Left (KeyError msg) -> return () -- do nothing
            fail -> assertFailure ("Expected a KeyError, got " ++ show fail)
    ]

cliTests = testGroup "Jweb CLI: application test"
    [ testProgram "Should successfully encrypt" "jweb-cli" ["encrypt", "data", "test/key1.pub"] Nothing
    , testProgram "Should successfully decrypt" "jweb-cli" ["decrypt", testJwe, "test/key1.priv"] Nothing
    ]

specTests = with (waiApp "test/static") $ do
    let matchPartial expected = MatchBody $ \_ body -> case C.isInfixOf expected (L.toStrict body) of
         True  -> Nothing
         False -> Just $  "Expected to find somewhere in body: " ++ C.unpack expected ++ ",\n"
                    ++ "Found: " ++ L.unpack body
    describe "/api/encrypt" $ do
        it "encrypts payload with a public key" $ do
            publicKeyData <- liftIO $ readFile "test/key1.pub"
            postHtmlForm "/api/encrypt" [("key", publicKeyData), ("payload", testData)] `shouldRespondWith` 200 {matchBody = matchPartial "\"jwe\":"}

        it "gives an error when using a private key" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/encrypt" [("key", privateKeyData), ("payload", testData)] `shouldRespondWith` [json| {error: "Could not parse public key"} |] {matchStatus = 400}

        it "gives an error for request missing 'payload' parameter" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/encrypt" [("key", privateKeyData)] `shouldRespondWith` [json| {error: "Param: payload not found!"} |] {matchStatus = 400}

        it "gives an error for request missing 'key' parameter" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/encrypt" [("payload", testData)] `shouldRespondWith` [json| {error: "Param: key not found!"} |] {matchStatus = 400}

    describe "/api/decrypt" $ do
        it "decrypts payload with a public key" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/decrypt" [("key", privateKeyData), ("jwe", testJwe)] `shouldRespondWith` [json| {header: {alg:"RSA-OAEP", enc: "A128GCM"}, payload: #{testData} } |]

        it "gives an error when using a public key" $ do
            publicKeyData <- liftIO $ readFile "test/key1.pub"
            postHtmlForm "/api/decrypt" [("key", publicKeyData), ("jwe", testJwe)] `shouldRespondWith` [json| {error: "Could not parse private key"} |] {matchStatus = 400}

        it "gives an error for request missing 'jwe' parameter" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/decrypt" [("key", privateKeyData)] `shouldRespondWith` [json| {error: "Param: jwe not found!"} |] {matchStatus = 400}

        it "gives an error for request missing 'key' parameter" $ do
            privateKeyData <- liftIO $ readFile "test/key1.priv"
            postHtmlForm "/api/decrypt" [("jwe", testJwe)] `shouldRespondWith` [json| {error: "Param: key not found!"} |] {matchStatus = 400}

    describe "static file serving" $ do
        it "serves static test file" $ do
            get "/test.html" `shouldRespondWith` 200

restTests :: IO TestTree
restTests = testSpec "Jweb REST API: application test" specTests
