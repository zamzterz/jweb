module Main where

import Jweb.App (scottyApp)
import Web.Scotty.Trans

main :: IO ()
main = scottyT 3000 id scottyApp