<?php

/**
 * HSMクライアントクラス
 */

class HSMClient
{
    private array $config;
    private HSMSocketManager $socketManager;
    private HSMCommandGenerator $commandGenerator;
    private HSMResponseParser $responseParser;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->socketManager = new HSMSocketManager($config);
        $this->commandGenerator = new HSMCommandGenerator($config);
        $this->responseParser = new HSMResponseParser();
    }

    /**
     * データブロックを暗号化する
     *
     * @param string $plaintext 暗号化対象文字列
     * @param string|null $ksn KSN（省略時はシステムKSNを使用）
     *
     * @return string 暗号化文字列
     * @throws Exception
     */
    public function encryptDataBlock(string $plaintext, ?string $ksn = null): string
    {
        return $this->executeWithConnection(function ($connection) use ($plaintext, $ksn) {
            // 送信データ生成
            $message = $this->commandGenerator->generateCommandEncryptDataBlock($plaintext, $ksn);

            // データ送信
            $this->sendMessage($message, $connection);

            // 応答受信
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100006');

            // 結果取得
            $resultText = $this->responseParser->parseResponseEncryptDataBlock($responseData);

            return $resultText;
        });
    }

    /**
     * 接続を開始し、処理後に接続を閉じる
     *
     * @param callable $callback
     *
     * @throws Exception
     *
     * @return mixed
     */
    protected function executeWithConnection(callable $callback): mixed
    {
        // 接続開始
        $this->socketManager->connect();

        try {
            // 処理実行
            $result = $callback($this->socketManager->getSocket());
        } finally {
            // 接続終了
            $this->socketManager->disconnect();
        }

        return $result;
    }

    /**
     * メッセージを送信
     *
     * @param string $message
     * @param resource $connection
     *
     * @throws Exception
     *
     * @return void
     */
    private function sendMessage(string $message, $connection): void
    {
        for (
            $written = $previousWritten = 0, $messageLength = strlen($message);
            $written < $messageLength;
            $written += $previousWritten
        ) {
            $msg = substr($message, $written);
            $previousWritten = fwrite($connection, $msg);
            if ($previousWritten === false) {
                throw new Exception('Failed to send message to HSM');
            }
        }

        // 開発用のログ全出力モードでなければ頭10桁のみ出力
        if ($this->config['logging']['fullOutputFlg']) {
            $sendMessage = $this->commandGenerator->getPayloadWithoutBinary($message);
        } else {
            $sendMessage = substr($this->commandGenerator->getPayloadWithoutBinary($message), 0, 10) . '...';
        }

        echo "Send: $sendMessage\n";
    }

    /**
     * 応答メッセージを取得し、エラーチェックを行う
     *
     * @param resource $connection
     * @param string $messageCode エラー時メッセージコード
     *
     * @throws Exception
     *
     * @return string
     */
    private function getResponseMessageWithCheckError($connection, string $messageCode): string
    {
        $responseData = $this->getResponseMessage($connection);
        $errorCode = $this->responseParser->getErrorCode($responseData);
        if ($errorCode !== HSMResponseParser::ERROR_CODE_NO_ERROR) {
            echo "HSM Error: ResponseCode=" . $this->responseParser->getResponseCode($responseData) . ", ErrorCode=$errorCode\n";
            throw new Exception("HSM Error: $messageCode");
        }

        return $responseData;
    }

    /**
     * 応答メッセージを取得
     *
     * @param resource $connection
     *
     * @throws Exception
     *
     * @return string
     */
    private function getResponseMessage($connection): string
    {
        $responseMessage = '';
        $receiveData = fread($connection, 2);
        if (!empty($receiveData)) {
            $len = unpack('n', $receiveData);
            if (!empty($len) && $len[1] > 0) {
                $dat = fread($connection, $len[1]);
                if (!empty($dat) && strlen($dat) == $len[1]) {
                    $responseMessage = $receiveData . $dat;
                } else {
                    throw new Exception('Failed to receive complete response from HSM');
                }
            }
        } else {
            throw new Exception('Failed to receive response from HSM');
        }

        // 開発用のログ全出力モードでなければ頭10桁のみ出力
        if ($this->config['logging']['fullOutputFlg']) {
            $receive = $this->commandGenerator->getPayloadWithoutBinary($responseMessage);
        } else {
            $receive = substr($this->commandGenerator->getPayloadWithoutBinary($responseMessage), 0, 10) . '...';
        }

        echo "Receive: $receive\n";

        return $responseMessage;
    }

    /**
     * データブロックをCBCモードで復号化して文字列として返す
     *
     * @param string $encryptedText 暗号化されたテキスト
     * @param string $ksn KSN
     * @return string 復号化された文字列
     * @throws Exception
     */
    public function decryptDataBlockWithCBCToString(string $encryptedText, string $ksn): string
    {
        return $this->executeWithConnection(function ($connection) use ($encryptedText, $ksn) {
            $message = $this->commandGenerator->generateCommandDecryptDataBlockWithCBC($encryptedText, $ksn);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100010');
            $plainText = $this->responseParser->parseResponseDecryptDataBlockWithIvToHex($responseData);
            return $plainText;
        });
    }

    /**
     * MACを生成する
     *
     * @param string $macTargetData MAC算出対象データ
     * @param string $ksn KSN
     * @return string MAC文字列
     * @throws Exception
     */
    public function generateMAC(string $macTargetData, string $ksn): string
    {
        return $this->executeWithConnection(function ($connection) use ($macTargetData, $ksn) {
            $message = $this->commandGenerator->generateCommandGenerateMac($macTargetData, $ksn);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E999999');
            $macString = $this->responseParser->parseResponseGenerateMAC($responseData);
            return $macString;
        });
    }

    /**
     * 公開鍵をHSMにインポート
     *
     * @param string $publicKey 公開鍵（バイナリデータ）
     * @return string 公開鍵MAC（バイナリデータ）
     * @throws Exception
     */
    public function importPublicKey(string $publicKey): string
    {
        return $this->executeWithConnection(function ($connection) use ($publicKey) {
            $message = $this->commandGenerator->generateCommandImportPublicKey($publicKey);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100007');
            $pubKeyMac = $this->responseParser->parseResponseImportPublicKey($responseData);
            return $pubKeyMac;
        });
    }

    /**
     * 公開鍵で暗号化されたTMKをエクスポート
     *
     * @param string $pubKeyMac 公開鍵MAC（バイナリデータ）
     * @return string 暗号化TMK（Base64エンコード）
     * @throws Exception
     */
    public function exportTMKEncryptedByPublicKey(string $pubKeyMac): string
    {
        return $this->executeWithConnection(function ($connection) use ($pubKeyMac) {
            $message = $this->commandGenerator->generateCommandExportKeyUnderPublicKey($pubKeyMac);
            $this->sendMessage($message, $connection);

            // 応答受信
            $responseData = $this->getResponseMessage($connection);
            $errorCode = $this->responseParser->getErrorCode($responseData);

            // エラーチェック
            if ($errorCode !== HSMResponseParser::ERROR_CODE_NO_ERROR) {
                $responseCode = $this->responseParser->getResponseCode($responseData);
                echo "HSM Error: ResponseCode=$responseCode, ErrorCode=$errorCode\n";
                throw new Exception("HSM Error: Failed to export TMK encrypted by public key (ErrorCode=$errorCode)");
            }

            $encryptedTmkBase64Encoded = $this->responseParser->parseResponseExportKeyUnderPublicKey($responseData);
            return $encryptedTmkBase64Encoded;
        });
    }

    /**
     * IPEKを生成してエクスポート（TR-31形式）
     *
     * @param string $iksn IKSN（Initial Key Serial Number）
     * @return array{ipekTr31: string, kcv: string} IPEK(TR-31形式)とKCV
     * @throws Exception
     */
    public function exportIPEKFormattedTR31(string $iksn): array
    {
        return $this->executeWithConnection(function ($connection) use ($iksn) {
            $message = $this->commandGenerator->generateCommandDeriveAndExportKeyFormattedTR31($iksn);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100009');
            $ipekWithKcv = $this->responseParser->parseResponseDeriveAndExportKeyFormattedTR31($responseData);
            return $ipekWithKcv;
        });
    }

    /**
     * IPEKを生成する
     *
     * @param string $iksn IKSN（Initial Key Serial Number）
     * @return array{ipek: string, kcv: string} IPEKとKCV
     * @throws Exception
     */
    public function deriveIPEK(string $iksn): array
    {
        return $this->executeWithConnection(function ($connection) use ($iksn) {
            $message = $this->commandGenerator->generateCommandDeriveIPEK($iksn);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100009');
            $ipek = $this->responseParser->parseResponseDeriveIPEK($responseData);
            return $ipek;
        });
    }

    /**
     * IPEKをTR-34形式でエクスポート
     *
     * @param string $ipek IPEK（形式未定、DeriveIPEK.phpで生成されたIPEK）
     * @param string $publicKey 公開鍵（バイナリデータ）
     * @return array{ipekTr34: string, kcv: string, signature: string} IPEK(TR-34形式、HEX文字列)、KCV(HEX文字列)、Signature(HEX文字列)
     * @throws Exception
     */
    public function exportIPEKformattedTR34(string $ipek, string $publicKey): array
    {
        return $this->executeWithConnection(function ($connection) use ($ipek, $publicKey) {
            $message = $this->commandGenerator->generateCommandExportIPEKformattedTR34($ipek, $publicKey);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100009');
            $ipekTr34 = $this->responseParser->parseResponseExportIPEKformattedTR34($responseData);
            return $ipekTr34;
        });
    }

    /**
     * キーコンポーネントからキーを生成
     *
     * @param string $keyComponent1 キーコンポーネント1
     * @param string $keyComponent2 キーコンポーネント2
     * @return string 生成されたキーの16進数文字列
     * @throws Exception
     */
    public function formKeyFromEncryptedComponents(string $keyComponent1, string $keyComponent2): string
    {
        return $this->executeWithConnection(function ($connection) use ($keyComponent1, $keyComponent2) {
            $message = $this->commandGenerator->generateCommandFormKeyFromEncryptedComponents($keyComponent1, $keyComponent2);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100012');
            $resultHex = $this->responseParser->parseResponseFormKeyFromEncryptedComponentsToHex($responseData);
            return $resultHex;
        });
    }

    /**
     * PIN暗号化を変換する
     *
     * @param string $zpk ZPK
     * @param string $ksn KSN
     * @param string $pinBlock PIN Block（16進数文字列）
     * @param string $accountNumber アカウント番号
     * @return string 変換後のPIN Block（16進数文字列）
     * @throws Exception
     */
    public function translatePinFromEncryption(string $zpk, string $ksn, string $pinBlock, string $accountNumber): string
    {
        return $this->executeWithConnection(function ($connection) use ($zpk, $ksn, $pinBlock, $accountNumber) {
            $message = $this->commandGenerator->generateCommandTranslatePinFromEncryption($zpk, $ksn, $pinBlock, $accountNumber);
            $this->sendMessage($message, $connection);
            $responseData = $this->getResponseMessageWithCheckError($connection, 'E100011');
            $destinationPinBlock = $this->responseParser->parseResponseTranslatePinFromEncryption($responseData);
            return $destinationPinBlock;
        });
    }
}
