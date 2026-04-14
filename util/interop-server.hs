{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

import Control.Concurrent (threadDelay)
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IP (IP)
import qualified Data.List as L
import Network.Socket (PortNumber)
import Network.TLS (Credentials (..), credentialLoadX509)
import qualified Network.TLS.SessionManager as SM
import System.Directory (doesFileExist)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.FilePath ((</>), isAbsolute, joinPath, splitDirectories)
import System.IO (BufferMode (..), hPutStrLn, hSetBuffering, stderr, stdout)

import Common (getLogger)
import InteropShared
import Network.QUIC
import Network.QUIC.Internal
import Network.QUIC.Server

-- Supported ALPNs for this interop target.
supportedALPNs :: [ByteString]
supportedALPNs = ["hq-interop", "hq-29", "siduck", "siduck-00"]

chooseALPN :: Version -> [ByteString] -> IO ByteString
chooseALPN _ offered =
    case L.find (`elem` supportedALPNs) offered of
        Just a -> return a
        Nothing -> return ""

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    _args <- getArgs -- ignored in harness mode
    tcStr <- envOr "TESTCASE" "handshake"
    sslKeyLog <- lookupEnv' "SSLKEYLOGFILE"
    certFile <- envOr "CERT_FILE" "/certs/cert.pem"
    keyFile <- envOr "KEY_FILE" "/certs/priv.key"
    rootDir <- envOr "ROOT_DIR" "/www"
    portStr <- envOr "PORT" "443"
    listenAddrs <- envOr "LISTEN" "0.0.0.0,::"
    alwaysRetry <- (== Just "1") <$> lookupEnv' "ALWAYS_RETRY"
    serverParams <- lookupEnv' "SERVER_PARAMS"
    mapM_ (\p -> hPutStrLn stderr ("note: SERVER_PARAMS ignored: " ++ p)) serverParams

    let tc = parseTestCase tcStr
    case tc of
        ChaCha20 -> exitUnsupported "chacha20"
        Unknown x -> exitUnsupported ("testcase " ++ x)
        _ -> return ()

    certExists <- doesFileExist certFile
    unless certExists $ do
        hPutStrLn stderr ("cert not found: " ++ certFile)
        exitFailure
    Right cred@(!_cc, !_priv) <- credentialLoadX509 certFile keyFile
    smgr <- SM.newSessionManager SM.defaultConfig

    let port = read portStr :: PortNumber
        addrs = [read a :: IP | a <- splitOn ',' listenAddrs]
        aps = (,port) <$> addrs

        sc0 = defaultServerConfig
        scBase =
            sc0
                { scAddresses = aps
                , scALPN = Just chooseALPN
                , scCredentials = Credentials [cred]
                , scSessionManager = smgr
                , scUse0RTT = True
                , scMaxDatagramFrameSize = 1500
                , scKeyLog = getLogger sslKeyLog
                , scRequireRetry = alwaysRetry
                }
        sc = applyTestCase tc scBase

    hPutStrLn stderr $ "interop-server: TESTCASE=" ++ tcStr ++ " ROOT=" ++ rootDir
    run sc (handleConnection rootDir)
    -- run returns when server stops; loop so container stays alive
    forever (threadDelay 60000000)

applyTestCase :: TestCase -> ServerConfig -> ServerConfig
applyTestCase Retry sc = sc{scRequireRetry = True}
applyTestCase _ sc = sc

handleConnection :: FilePath -> Connection -> IO ()
handleConnection rootDir conn = do
    info <- getConnectionInfo conn
    case alpn info of
        Just a
            | a == "siduck" || a == "siduck-00" -> serveSiduck conn
            | "hq" `BS.isPrefixOf` a -> serveHQ rootDir conn
        _ -> return ()

----------------------------------------------------------------
-- HQ (HTTP/0.9) handler

serveHQ :: FilePath -> Connection -> IO ()
serveHQ rootDir conn = loop
  where
    loop = do
        ms <- E.try (acceptStream conn) :: IO (Either E.SomeException Stream)
        case ms of
            Left _ -> return ()
            Right s -> do
                let sid = streamId s
                if isClientInitiatedBidirectional sid
                    then do
                        _ <- E.try (handleStream rootDir s) :: IO (Either E.SomeException ())
                        loop
                    else loop

handleStream :: FilePath -> Stream -> IO ()
handleStream rootDir s = do
    reqLine <- readRequestLine s ""
    case parseGet reqLine of
        Nothing -> do
            sendStream s "BAD REQUEST"
            closeStream s
        Just path ->
            case resolvePath rootDir path of
                Nothing -> do
                    sendStream s "BAD REQUEST"
                    closeStream s
                Just fp -> do
                    exists <- doesFileExist fp
                    if not exists
                        then do
                            sendStream s "BAD REQUEST"
                            closeStream s
                        else streamFile s fp

-- | Read until CR or LF. Caps at 8 KiB to guard against abuse.
readRequestLine :: Stream -> ByteString -> IO ByteString
readRequestLine s acc
    | BS.length acc > 8192 = return acc
    | otherwise = do
        bs <- recvStream s 1024
        if BS.null bs
            then return acc
            else do
                let joined = acc `BS.append` bs
                case BS.findIndex (\c -> c == 0x0a || c == 0x0d) joined of
                    Just _ -> return joined
                    Nothing -> readRequestLine s joined

parseGet :: ByteString -> Maybe ByteString
parseGet bs
    | BS.length bs < 5 = Nothing
    | BS.map asciiLower (BS.take 4 bs) /= "get " = Nothing
    | otherwise =
        let rest = BS.drop 4 bs
            terminator c = c == 0x20 || c == 0x0a || c == 0x0d
            path = BS.takeWhile (not . terminator) rest
         in if BS.null path then Nothing else Just path
  where
    asciiLower c
        | 0x41 <= c && c <= 0x5a = c + 0x20
        | otherwise = c

-- | Map URL path to filesystem, refusing "..". Returns absolute path under root.
resolvePath :: FilePath -> ByteString -> Maybe FilePath
resolvePath rootDir pathBS =
    let pathStr = C8.unpack pathBS
        cleaned = dropWhile (== '/') pathStr
        parts = splitDirectories cleaned
     in if any badPart parts
            then Nothing
            else Just (rootDir </> joinPath parts)
  where
    badPart p = p == ".." || p == "." || isAbsolute p || '/' `elem` p

streamFile :: Stream -> FilePath -> IO ()
streamFile s fp = do
    body <- BS.readFile fp
    sendChunks body
    closeStream s
  where
    chunk = 65536
    sendChunks bs
        | BS.null bs = return ()
        | otherwise = do
            let (h, t) = BS.splitAt chunk bs
            sendStream s h
            sendChunks t

----------------------------------------------------------------
-- siduck

serveSiduck :: Connection -> IO ()
serveSiduck conn = loop
  where
    loop = do
        mbs <- E.try (recvDatagram conn) :: IO (Either E.SomeException ByteString)
        case mbs of
            Left _ -> return ()
            Right bs
                | bs == "quack" -> do
                    sendDatagram conn "quack-ack"
                    loop
                | otherwise ->
                    abortConnection conn (ApplicationProtocolError 0x101) "SIDUCK_ONLY_QUACKS_ECHO"

----------------------------------------------------------------

splitOn :: Char -> String -> [String]
splitOn _ "" = []
splitOn c s = case break (== c) s of
    (x, "") -> [x]
    (x, _ : r) -> x : splitOn c r
