{-# LANGUAGE OverloadedStrings #-}

module Jweb.App (scottyApp, waiApp) where

import qualified Data.ByteString.Char8 as C
import qualified Data.Text as T
import qualified Data.Text.Lazy as L
import qualified Data.Text.Encoding as TE

import Data.Aeson (object, (.=), toJSON)
import Data.Monoid (mconcat)
import Data.String (fromString)

import qualified Jose.Jwt as Jwt
import Jweb.Encrypt (encrypt)
import Jweb.Decrypt (decrypt)

import Network.HTTP.Types.Status
import Network.Wai
import Network.Wai.Middleware.RequestLogger

import Web.Scotty.Trans


data Except = BadRequest String | InternalServerError String | StringEx String
    deriving (Eq)
instance ScottyError Except where
    stringError = StringEx
    showError = fromString . show

instance Show Except where
    show (StringEx msg) = msg
    show (BadRequest msg) = msg
    show (InternalServerError msg) = msg

handleEx :: Monad m => Except -> ActionT Except m ()
handleEx (BadRequest e) = do
    status status400
    json $ object [ "error" .= e ]
handleEx (InternalServerError e) = do
    status status500
    json $ object [ "error" .= e ]
handleEx (StringEx e) = do
    status status500
    json $ object [ "error" .= e ]

scottyApp :: ScottyT Except IO ()
scottyApp = do
    middleware logStdout
    defaultHandler handleEx

    post "/api/encrypt" $ do
        key <- param "key" `rescue` (\(StringEx m) -> raise (BadRequest $ fromString m))
        payload <- param "payload" `rescue` (\(StringEx m) -> raise (BadRequest $ fromString m))
        jwe <- liftAndCatchIO $ encrypt (L.unpack key) (TE.encodeUtf8 (L.toStrict payload))
        case jwe of
            Right jwe -> json $ object [ "jwe" .= jwe ]
            Left (Jwt.KeyError error) -> raise (BadRequest (T.unpack error))
            Left error -> raise (InternalServerError (show error))

    post "/api/decrypt" $ do
        key <- param "key" `rescue` (\(StringEx m) -> raise (BadRequest $ fromString m))
        jwe <- param "jwe" `rescue` (\(StringEx m) -> raise (BadRequest $ fromString m))
        decrypted <- liftAndCatchIO $ decrypt (L.unpack key) (TE.encodeUtf8 (L.toStrict jwe))
        case decrypted of
            Right (Jwt.Jwe (header, payload)) -> json $ object [ "header" .= header, "payload" .= C.unpack payload]
            Left (Jwt.KeyError error) -> raise (BadRequest (T.unpack error))
            Left error -> raise (InternalServerError (show error))

waiApp :: IO Application
waiApp = scottyAppT id scottyApp

