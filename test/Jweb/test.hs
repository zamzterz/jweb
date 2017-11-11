import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString.Char8 as C

import Jose.Jwk
import Jose.Jwt
import Jweb.Encrypt
import Jweb.Decrypt

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [unitTests]

unitTests = testGroup "Unit tests"
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
