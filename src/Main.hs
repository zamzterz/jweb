module Main where

import qualified Data.ByteString as B

import Jose.Jws
import Jose.Jwa
import Jose.Jwt

createJWS :: B.ByteString -> Either JwtError Jwt
createJWS payload = hmacEncode HS256 "supersecretkey" payload

main = do
 putStrLn "Input JWS payload"
 payload <- B.getLine
 case (createJWS bytes) of
    Right (Jwt signed) -> putStrLn (show signed)
    Left error -> putStrLn ("JWS couldn't be created :" ++ (show error))

