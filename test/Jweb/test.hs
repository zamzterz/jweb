import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.Program

import qualified Data.ByteString.Char8 as C

import Jose.Jwk
import Jose.Jwt
import Jweb.Encrypt
import Jweb.Decrypt

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [jwebUnitTests, cliTests]

testJwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.Gl_JYiuaDbTiASvXoxdAU2srn9bolXBEd7h5eagCbwx1hxBWi-SLkKf34sgg0DIBwJ7DxNSDgtOrFcNxLWcy1w.3mfMQb0YVn_cmCdv.e2G1sA.sQkBo1l32d3Xunw9VNPK9A"

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
        Left (BadCrypto)  @=? decrypted
    ]

cliTests = testGroup "Jweb CLI: application test"
    [ testProgram "Should successfully encrypt" "jweb-cli" ["encrypt", "data", "test/key1.pub"] Nothing
    , testProgram "Should successfully decrypt" "jweb-cli" ["decrypt", testJwe, "test/key1.priv"] Nothing
    ]
