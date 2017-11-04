{-# LANGUAGE OverloadedStrings #-}

module Jweb.Decrypt (decrypt) where

import Jose.Jwa
import Jose.Jwe
import Jose.Jwk
import Jose.Jwt

import qualified Data.ByteString as B

import qualified Crypto.PubKey.RSA as RSA
import OpenSSL.EVP.PKey
import OpenSSL.PEM
import OpenSSL.RSA

import Crypto.Random (MonadRandom)

-- | Decrypt a JWE with the private key given by the file path.
decrypt :: FilePath -> B.ByteString -> IO (Either JwtError JwtContent)
decrypt privateKeyPath jwt = do
    privateKey <- createPrivateKeyJwk privateKeyPath
    case privateKey of
        Just key -> unpackJwe key jwt
        Nothing -> return (Left (KeyError "Could not parse private key"))

-- | Create a JWK from a private RSA key in PEM format read from file.
createPrivateKeyJwk :: FilePath -> IO (Maybe Jwk)
createPrivateKeyJwk rsaKeyFilePath = do
    rsaPrivateKeyData <- readFile rsaKeyFilePath
    parsedRsaPrivateKey <- readPrivateKey rsaPrivateKeyData PwNone
    let rsaPrivateKey = toKeyPair parsedRsaPrivateKey :: Maybe RSAKeyPair
    return (fmap privateRsaKeyToJwk rsaPrivateKey)

-- Map a private key in a RSA key pair to a JWK.
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

-- | Decrypt data with the given key.
unpackJwe :: MonadRandom m => Jwk -> B.ByteString -> m (Either JwtError JwtContent)
unpackJwe privateKey jwt = jwkDecode privateKey jwt

