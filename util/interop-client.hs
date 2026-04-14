{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (threadDelay)
import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Network.TLS (HandshakeMode13 (..))
import System.Directory (createDirectoryIfMissing, setCurrentDirectory)
import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitWith)
import System.FilePath (takeFileName)
import System.IO (BufferMode (..), hPutStrLn, hSetBuffering, stderr, stdout)

import Common (getLogger)
import InteropShared
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal (
    Version,
    ccKeyLog,
    ccVersion,
    pattern GreasingVersion,
    pattern Version1,
    pattern Version2,
 )

main :: IO ()
main = do
    hSetBuffering stdout NoBuffering
    _args <- getArgs
    tcStr <- envOr "TESTCASE" "handshake"
    sslKeyLog <- lookupEnv' "SSLKEYLOGFILE"
    requestsRaw <- envOr "REQUESTS" ""
    downloadsDir <- lookupEnv' "DOWNLOADS"
    clientParams <- lookupEnv' "CLIENT_PARAMS"
    mapM_ (\p -> hPutStrLn stderr ("note: CLIENT_PARAMS ignored: " ++ p)) clientParams

    let tc = parseTestCase tcStr
    case tc of
        ChaCha20 -> exitUnsupported "chacha20"
        Unknown x -> exitUnsupported ("testcase " ++ x)
        _ -> return ()

    case downloadsDir of
        Just d -> do
            createDirectoryIfMissing True d
            setCurrentDirectory d
        Nothing -> return ()

    let reqs = mapM parseRequest (words requestsRaw)
    parsedReqs <- case reqs of
        Just rs | not (null rs) -> return rs
        _
            | tc == Handshake || tc == VerNego || tc == Retry
            , Just r <- parseRequest "https://127.0.0.1:4433/" ->
                return [r]
        _ -> do
            hPutStrLn stderr "REQUESTS empty or malformed"
            exitWith (ExitFailure 1)

    hPutStrLn stderr $ "interop-client: TESTCASE=" ++ tcStr ++ " reqs=" ++ show (length parsedReqs)

    let baseCC =
            defaultClientConfig
                { ccServerName = reqHost (head parsedReqs)
                , ccPortName = reqPort (head parsedReqs)
                , ccALPN = alpnFor tc
                , ccValidate = False
                , ccKeyLog = getLogger sslKeyLog
                , ccMaxDatagramFrameSize = if tc == Siduck then 1500 else 0
                }
    result <- E.try (runTest tc baseCC parsedReqs) :: IO (Either E.SomeException TestOutcome)
    case result of
        Right Pass -> do
            hPutStrLn stderr ("interop-client: PASS (" ++ tcStr ++ ")")
            exitWith ExitSuccess
        Right (Fail reason) -> do
            hPutStrLn stderr ("interop-client: FAIL (" ++ tcStr ++ "): " ++ reason)
            exitWith (ExitFailure 1)
        Left e -> do
            hPutStrLn stderr ("interop-client: FAIL (" ++ tcStr ++ "): exception: " ++ show e)
            exitWith (ExitFailure 1)

alpnFor :: TestCase -> Version -> IO (Maybe [ByteString])
alpnFor Siduck = \_ -> return (Just ["siduck", "siduck-00"])
alpnFor _ = \_ -> return (Just ["hq-interop", "hq-29"])

data TestOutcome = Pass | Fail String

runTest :: TestCase -> ClientConfig -> [Request] -> IO TestOutcome

runTest Handshake cc _ = run cc $ \conn -> do
    waitEstablished conn
    info <- getConnectionInfo conn
    case alpn info of
        Just _ -> return Pass
        Nothing -> return (Fail "no ALPN negotiated")

runTest Transfer cc reqs = run cc $ \conn -> do
    waitEstablished conn
    oks <- mapM (downloadOne conn) reqs
    return $ if all id oks then Pass else Fail "transfer mismatch"

runTest MultiConnect cc reqs = do
    oks <- mapM perUrl reqs
    return $ if all id oks then Pass else Fail "multiconnect transfer mismatch"
  where
    perUrl r = do
        let cc' = cc{ccServerName = reqHost r, ccPortName = reqPort r}
        run cc' $ \conn -> do
            waitEstablished conn
            downloadOne conn r

runTest Retry cc _ = run cc $ \conn -> do
    waitEstablished conn
    info <- getConnectionInfo conn
    return $
        if retry info
            then Pass
            else Fail "retry not observed"

runTest VerNego cc0 _ = do
    let cc = cc0{ccVersions = [GreasingVersion, Version2, Version1]}
    run cc $ \conn -> do
        waitEstablished conn
        info <- getConnectionInfo conn
        let v = version info
        return $
            if v == Version1 || v == Version2
                then Pass
                else Fail ("unexpected version: " ++ show v)

runTest V2 cc0 _ = do
    let cc = cc0{ccVersions = [Version2, Version1], ccVersion = Version2}
    run cc $ \conn -> do
        waitEstablished conn
        info <- getConnectionInfo conn
        return $
            if version info == Version2
                then Pass
                else Fail ("negotiated " ++ show (version info) ++ ", expected Version2")

runTest Resumption cc reqs = do
    res <- run cc $ \conn -> do
        waitEstablished conn
        _ <- downloadOne conn (head reqs)
        threadDelay 50000
        getResumptionInfo conn
    if not (isResumptionPossible res)
        then return (Fail "no resumption ticket issued")
        else do
            threadDelay 100000
            let cc2 = cc{ccResumption = res}
            run cc2 $ \conn -> do
                waitEstablished conn
                info <- getConnectionInfo conn
                ok <- downloadOne conn (head reqs)
                return $
                    case (handshakeMode info, ok) of
                        (PreSharedKey, True) -> Pass
                        (PreSharedKey, False) -> Fail "resumed but download failed"
                        (m, _) -> Fail ("resumed handshake mode " ++ show m)

runTest ZeroRTT cc reqs = do
    res <- run cc $ \conn -> do
        waitEstablished conn
        _ <- downloadOne conn (head reqs)
        threadDelay 50000
        getResumptionInfo conn
    if not (is0RTTPossible res)
        then return (Fail "0-RTT not offered")
        else do
            threadDelay 100000
            let cc2 = cc{ccResumption = res, ccUse0RTT = True}
            run cc2 $ \conn -> do
                ok <- downloadOne0RTT conn (head reqs)
                info <- getConnectionInfo conn
                return $
                    case (handshakeMode info, ok) of
                        (RTT0, True) -> Pass
                        (RTT0, False) -> Fail "0-RTT accepted but download failed"
                        (m, _) -> Fail ("handshake mode " ++ show m)

runTest KeyUpdate cc reqs = run cc $ \conn -> do
    waitEstablished conn
    oks <- mapM (downloadOne conn) reqs
    return $ if all id oks then Pass else Fail "transfer failed"

runTest Siduck cc _ = run cc $ \conn -> do
    waitEstablished conn
    sendDatagram conn "quack"
    bs <- recvDatagram conn
    return $
        if bs == "quack-ack"
            then Pass
            else Fail ("got datagram " ++ show bs)

runTest ChaCha20 _ _ = exitUnsupported "chacha20"
runTest (Unknown x) _ _ = exitUnsupported ("testcase " ++ x)

----------------------------------------------------------------
-- Download logic (HQ / HTTP-0.9)

downloadOne :: Connection -> Request -> IO Bool
downloadOne conn r = do
    s <- stream conn
    sendStream s (C8.pack ("GET " ++ reqPath r ++ "\r\n"))
    shutdownStream s
    saveToFile (outputPath r) s

downloadOne0RTT :: Connection -> Request -> IO Bool
downloadOne0RTT conn r = do
    s <- stream conn
    sendStream s (C8.pack ("GET " ++ reqPath r ++ "\r\n"))
    shutdownStream s
    saveToFile (outputPath r) s

outputPath :: Request -> FilePath
outputPath r =
    let base = takeFileName (reqPath r)
     in if null base then "index" else base

saveToFile :: FilePath -> Stream -> IO Bool
saveToFile fp s = do
    E.bracket (return ()) (\_ -> closeStream s) $ \_ ->
        loop BS.empty
  where
    loop acc = do
        bs <- recvStream s 65536
        if BS.null bs
            then do
                BS.writeFile fp acc
                return True
            else loop (acc `BS.append` bs)
