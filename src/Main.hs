{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import Jose.Jwa
import Jose.Jwe
import Jose.Jwk
import Jose.Jwt

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Crypto.PubKey.RSA as RSA

import OpenSSL.EVP.PKey
import OpenSSL.PEM
import OpenSSL.RSA

import System.Console.CmdArgs
import System.Exit (exitFailure)

createPublicKeyJwk :: FilePath -> IO Jwk
createPublicKeyJwk rsaKeyFilePath = do
    rsaPublicKeyData <- readFile rsaKeyFilePath
    parsedRsaPublicKey <- readPublicKey rsaPublicKeyData
    let rsaPublicKey = toPublicKey parsedRsaPublicKey :: Maybe RSAPubKey
    case rsaPublicKey of
        Just (rsa) -> return (publicRsaKeyToJwk rsa)
        Nothing -> do
            putStrLn "Could not convert RSA key to public key"
            exitFailure

publicRsaKeyToJwk :: RSAPubKey -> Jwk
publicRsaKeyToJwk rsa = RsaPublicJwk (RSA.PublicKey
                         { RSA.public_size = size
                         , RSA.public_n = n
                         , RSA.public_e = e
                         }) Nothing Nothing Nothing
                        where size = rsaSize rsa
                              n = rsaN rsa
                              e = rsaE rsa


encrypt :: FilePath -> B.ByteString -> IO (Either JwtError Jwt)
encrypt publicKeyPath claims = do
    publicKey <- createPublicKeyJwk publicKeyPath
    createJwe publicKey claims

createJwe :: Jwk -> B.ByteString -> IO (Either JwtError Jwt)
createJwe publicKey claims = jwkEncode RSA_OAEP A128GCM publicKey (Claims claims)

handleEncryption payload publicKeyPath = do
    jwe <- encrypt publicKeyPath (C.pack payload)
    case jwe of
        Right (Jwt jwt) -> print jwt
        Left error -> print error

handleDecryption jwt privateKeyPath = do
    decrypted <- decrypt privateKeyPath (C.pack jwt)
    case decrypted of
        Right (Jwe (hdr, claims)) -> putStrLn (show hdr ++ "." ++ show claims)
        Left error -> print error

decrypt :: FilePath -> B.ByteString -> IO (Either JwtError JwtContent)
decrypt privateKeyPath jwt = do
    privateKey <- createPrivateKeyJwk privateKeyPath
    unpackJwe privateKey jwt

createPrivateKeyJwk :: FilePath -> IO Jwk
createPrivateKeyJwk rsaKeyFilePath = do
    rsaPrivateKeyData <- readFile rsaKeyFilePath
    parsedRsaPrivateKey <- readPrivateKey rsaPrivateKeyData PwNone
    let rsaPrivateKey = toKeyPair parsedRsaPrivateKey :: Maybe RSAKeyPair
    case rsaPrivateKey of
        Just (rsa) -> return (privateRsaKeyToJwk rsa)
        Nothing -> do
            putStrLn "Could not convert RSA key to private key"
            exitFailure

privateRsaKeyToJwk :: RSAKeyPair -> Jwk
privateRsaKeyToJwk rsa = RsaPrivateJwk (RSA.PrivateKey
                         { RSA.private_pub = rsaPub
                         , RSA.private_d = d
                         , RSA.private_p = p
                         , RSA.private_q = q
                         , RSA.private_dP = maybe 0 id dp
                         , RSA.private_dQ = maybe 0 id dq
                         , RSA.private_qinv = maybe 0 id qinv
                         }) Nothing Nothing Nothing
                        where rsaPub = RSA.PublicKey { RSA.public_size = rsaSize rsa, RSA.public_n = rsaN rsa, RSA.public_e = rsaE rsa }
                              d = rsaD rsa
                              p = rsaP rsa
                              q = rsaQ rsa
                              dp = rsaDMP1 rsa
                              dq = rsaDMQ1 rsa
                              qinv = rsaIQMP rsa

unpackJwe :: Jwk -> B.ByteString -> IO (Either JwtError JwtContent)
unpackJwe privateKey jwt = jwkDecode privateKey jwt

data Jweb = Encrypt {payload :: String, publicKeyPath :: FilePath}
          | Decrypt {jwt :: String, privateKeyPath :: FilePath}
            deriving (Data, Typeable, Show, Eq)

encryptMode = Encrypt
    {payload = def &= argPos 0 &= typ "JSON"
    ,publicKeyPath = def &= argPos 1 &= typFile
    } &= help "Encrypt some data"
decryptMode = Decrypt
    {jwt = def &= argPos 2 &= typ "ENCRYPTED"
    ,privateKeyPath = def &= argPos 3 &= typFile
    } &= help "Decrypt a JWE"
options = modes [encryptMode, decryptMode]
     &= program "jweb cli"
main = do
    command <- cmdArgs options
    case command of
        Encrypt payload publicKeyPath -> handleEncryption payload publicKeyPath
        Decrypt jwt privateKeyPath -> handleDecryption jwt privateKeyPath
