{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import qualified Data.ByteString.Char8 as C

import System.Console.CmdArgs
import Jose.Jwt

import Jweb.Encrypt
import Jweb.Decrypt

handleEncryption publicKeyData payload = do
    jwe <- encrypt publicKeyData (C.pack payload)
    case jwe of
        Left error -> print error
        Right (Jwt jwt) -> putStrLn (C.unpack jwt)

handleDecryption privateKeyData jwt = do
    decrypted <- decrypt privateKeyData (C.pack jwt)
    case decrypted of
        Right (Jwe (hdr, claims)) -> putStrLn (show hdr ++ "." ++ show claims)
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
        Encrypt payload publicKeyPath -> do
            publicKeyData <- readFile publicKeyPath
            handleEncryption publicKeyData payload
        Decrypt jwt privateKeyPath -> do
            privateKeyData <- readFile privateKeyPath
            handleDecryption privateKeyData jwt
