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

        step "Encrypting"
        Right (Jwt encrypted) <- encrypt "test/key1.pub" (C.pack testData)

        step "Decrypting"
        Right (Jwe (hdr, claims)) <- decrypt "test/key1.priv" encrypted

        step "Asserting"
        testData @=? C.unpack claims

    , testCaseSteps "Should reject decryption with wrong key" $ \step -> do
        step "Encrypting with key1.pub"
        Right (Jwt encrypted) <- encrypt "test/key1.pub" (C.pack "test_data")

        step "Decrypting with key2.priv"
        decrypted <- decrypt "test/key2.priv" encrypted
        Left (BadCrypto)  @=? decrypted
    ]
