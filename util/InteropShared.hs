{-# LANGUAGE OverloadedStrings #-}

module InteropShared (
    TestCase (..),
    parseTestCase,
    exitUnsupported,
    lookupEnv',
    envOr,
    parseRequest,
    Request (..),
) where

import Data.Char (toLower)
import Data.List (stripPrefix)
import System.Environment (lookupEnv)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hPutStrLn, stderr)

data TestCase
    = VerNego
    | Handshake
    | Transfer
    | MultiConnect
    | Retry
    | Resumption
    | ZeroRTT
    | KeyUpdate
    | V2
    | Siduck
    | ChaCha20
    | Unknown String
    deriving (Show, Eq)

parseTestCase :: String -> TestCase
parseTestCase s = case map toLower s of
    "versionnegotiation" -> VerNego
    "handshake" -> Handshake
    "transfer" -> Transfer
    "multiconnect" -> MultiConnect
    "retry" -> Retry
    "resumption" -> Resumption
    "zerortt" -> ZeroRTT
    "keyupdate" -> KeyUpdate
    "v2" -> V2
    "siduck" -> Siduck
    "chacha20" -> ChaCha20
    other -> Unknown other

exitUnsupported :: String -> IO a
exitUnsupported reason = do
    hPutStrLn stderr $ "unsupported: " ++ reason
    exitWith (ExitFailure 127)

lookupEnv' :: String -> IO (Maybe String)
lookupEnv' = lookupEnv

envOr :: String -> String -> IO String
envOr name dflt = maybe dflt id <$> lookupEnv name

data Request = Request
    { reqHost :: String
    , reqPort :: String
    , reqPath :: String
    }
    deriving (Show)

-- | Parse a URL like "https://host:port/path" or "https://host/path".
parseRequest :: String -> Maybe Request
parseRequest url0 = do
    url <- stripScheme url0
    let (hostport, path) = break (== '/') url
        (h, p) = splitHostPort hostport
        pth = if null path then "/" else path
    return (Request h p pth)
  where
    stripScheme u
        | Just r <- stripPrefix "https://" u = Just r
        | Just r <- stripPrefix "http://" u = Just r
        | Just r <- stripPrefix "quic://" u = Just r
        | otherwise = Just u
    splitHostPort hp = case break (== ':') (dropBrackets hp) of
        (h, ':' : p) -> (h, p)
        (h, _) -> (h, "443")
    -- Handle bracketed IPv6 [::1]:443
    dropBrackets ('[' : rest)
        | (a, ']' : b) <- break (== ']') rest = a ++ b
    dropBrackets s = s
