{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as B

import Jose.Jwe
import Jose.Jwa
import Jose.Jwt
import Jose.Jwk (generateRsaKeyPair, generateSymmetricKey, KeyUse(Enc), KeyId)

import System.IO

encrypt publicKey claims = jwkEncode RSA_OAEP A128GCM publicKey (Claims claims)
decrypt privateKey jwe = jwkDecode privateKey jwe

processEncrypted jwt privateKey = do
    putStrLn ("Encrypted: " ++ show jwt)
    decrypted <- decrypt privateKey jwt
    case (decrypted) of
        Right (Jwe (hdr, claims)) -> putStrLn ("Decrypted: " ++ show claims)
        Left error -> putStrLn ("JWE couldn't be decrypted :" ++ (show error))
main = do
 hSetBuffering stdout NoBuffering
 putStrLn "Input JWE claims"
 claims <- B.getLine

 --  create key pair
 (kPub, kPr) <- generateRsaKeyPair 512 (KeyId "test_key") Enc Nothing -- TODO how can KeyId be omitted?
 putStrLn (show kPub) -- TODO read public key from stdin instead
 putStrLn (show kPr)
 encrypted <- encrypt kPub claims
 case (encrypted) of
    Right (Jwt jwt) -> processEncrypted jwt kPr
    Left error -> putStrLn ("JWE couldn't be created :" ++ (show error))
