{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import Jose.Jwa
import Jose.Jwe
import Jose.Jwk
import Jose.Jwt

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import qualified Crypto.PubKey.RSA as RSA

import OpenSSL.PEM
import OpenSSL.RSA
import OpenSSL.EVP.PKey

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
        Decrypt jwt privateKeyPath -> print "Decryption is not yet supported!"