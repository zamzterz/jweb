{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import qualified Data.ByteString.Char8 as C

import System.Console.CmdArgs
import Jose.Jwt

import Encrypt
import Decrypt

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
