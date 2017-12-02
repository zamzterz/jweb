module Main where

import Jweb.App (scottyApp)
import System.Environment
import Web.Scotty.Trans

main :: IO ()
main = do
    staticDir <- getEnv "JWEB_STATIC_DIR"
    scottyT 3000 id (scottyApp staticDir)
