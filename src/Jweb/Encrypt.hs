{-# LANGUAGE OverloadedStrings #-}

module Jweb.Encrypt (encrypt) where

import Jose.Jwa
import Jose.Jwe
import Jose.Jwk
import Jose.Jwt

import qualified Data.ByteString as B

import System.IO.Error (tryIOError)

import qualified Crypto.PubKey.RSA as RSA
import OpenSSL.EVP.PKey
import OpenSSL.PEM
import OpenSSL.RSA

import Crypto.Random (MonadRandom)

-- | Create a JWE, encrypting the given data with the public key given by the file path.
encrypt :: String -> B.ByteString -> IO (Either JwtError Jwt)
encrypt publicKeyData claims = do
    publicKey <- createPublicKeyJwk publicKeyData
    case publicKey of
        Just key -> createJwe key claims
        Nothing -> return (Left (KeyError "Could not parse public key"))

-- | Create a JWK from a public RSA key in PEM format read from file.
createPublicKeyJwk :: String -> IO (Maybe Jwk)
createPublicKeyJwk rsaPublicKeyData = do
    parsedRsaPublicKey <- tryIOError (readPublicKey rsaPublicKeyData)
    case parsedRsaPublicKey of
        Right key -> do
            let rsaPublicKey = toPublicKey key
            return (fmap publicRsaKeyToJwk rsaPublicKey)
        _ -> return Nothing

-- Map a public RSA key to a JWK.
publicRsaKeyToJwk :: RSAPubKey -> Jwk
publicRsaKeyToJwk rsa = RsaPublicJwk (RSA.PublicKey
                         { RSA.public_size = size
                         , RSA.public_n = n
                         , RSA.public_e = e
                         }) Nothing Nothing Nothing
                        where size = rsaSize rsa
                              n = rsaN rsa
                              e = rsaE rsa

-- | Encrypt data with the given key.
createJwe :: MonadRandom m => Jwk -> B.ByteString -> m (Either JwtError Jwt)
createJwe publicKey claims = jwkEncode RSA_OAEP A128GCM publicKey (Claims claims)
