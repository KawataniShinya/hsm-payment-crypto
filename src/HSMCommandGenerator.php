<?php

/**
 * HSMコマンド生成クラス
 */

class HSMCommandGenerator
{
    private string $hsmBdkBlock;
    private string $hsmTmkBlock;
    private string $hsmTmkMac;
    private string $systemKsn;

    public function __construct(array $config)
    {
        $this->hsmBdkBlock = $config['hsm']['bdk_block_3des'];
        $this->hsmTmkBlock = $config['hsm']['tmk_block'] ?? '';
        $this->hsmTmkMac = $config['hsm']['tmk_mac'] ?? '';
        $this->systemKsn = '5354393939FFFFE00000'; // デフォルトのシステムKSN

        if (!$this->hsmBdkBlock) {
            throw new Exception('HSM configuration is incomplete');
        }
    }

    /**
     * Encrypt Data Block コマンド(M0)の生成
     *
     * @param string $plaintext
     * @param string|null $ksn
     *
     * @return string
     */
    public function generateCommandEncryptDataBlock(string $plaintext, ?string $ksn = null): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'M0'; // Encrypt Data Block
        $modeFlag = sprintf('%02d', 1); // CBC (requires an IV)
        $inputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $outputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $keyType = 'FFF'; // For a Key Block LMK (This field is ignored)
        $keyAt32 = $this->hsmBdkBlock;
        $ksnDescriptor = 'A05';
        $ksnAt20 = strtoupper($ksn ?? $this->systemKsn);
        $iv = sprintf('%016X', 0);
        list($targetText, $messageLength) = $this->getTargetText($plaintext);
        $endMessageDelimiter = '';
        $messageTrailer = '';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $commandCode .
            $modeFlag .
            $inputFormatFlag .
            $outputFormatFlag .
            $keyType .
            $keyAt32 .
            $ksnDescriptor .
            $ksnAt20 .
            $iv .
            $messageLength .
            $targetText .
            $endMessageDelimiter .
            $messageTrailer;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * 対象文字列の整形と桁数の取得
     * 80 00 00... 形式でパディング。
     * 可変長データ,桁不足の場合は、8000...パディングを行う。
     *
     * @param string $plaintext
     *
     * @return array<int, string>
     */
    private function getTargetText(string $plaintext): array
    {
        // 制御文字の追加
        $targetText = sprintf('%-' . "'" . chr(128) . (strlen($plaintext) + 1) . 's', $plaintext);

        // 8の倍数まで0埋めしてパディング
        $targetText = sprintf(
            '%-' . "'" . chr(0) . (ceil(strlen($targetText) / 8) * 8) . 's',
            $targetText
        );

        // $inputFormatFlagが1の場合のhex変換
        $targetText = strtoupper(bin2hex($targetText));
        $messageLength = sprintf('%04X', strlen($targetText));

        return [$targetText, $messageLength];
    }

    /**
     * HSM応答からテキスト表示可能な文字列を抽出
     *
     * @param string $message
     *
     * @return string
     */
    public function getPayloadWithoutBinary(string $message): string
    {
        // 制御文字の部分をカット
        $payload = substr($message, 2);

        $nonBinaryPart = '';

        // 各文字を確認
        for ($i = 0; $i < strlen($payload); $i++) {
            // 文字が表示可能なASCIIかどうかチェック
            $asciiValue = ord($payload[$i]);

            // ASCII 32以上127未満の範囲は表示可能な文字
            if ($asciiValue >= 32 && $asciiValue < 127) {
                $nonBinaryPart .= $payload[$i];
            } else {
                // バイナリ文字が見つかったら、これまでの文字列を返す
                return $nonBinaryPart;
            }
        }

        // バイナリ文字がない場合は全体を返す
        return $nonBinaryPart;
    }

    /**
     * Decrypt Data Block コマンド(M2)の生成
     *
     * @param string $encryptedText 暗号化文字列
     * @param string $ksn           KSN
     *
     * @return string
     */
    public function generateCommandDecryptDataBlockWithCBC(string $encryptedText, string $ksn): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'M2'; // Decrypt Data Block
        $modeFlag = sprintf('%02d', 1); // CBC (requires an IV)
        $inputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $outputFormatFlag = sprintf('%01d', 0); // Binary
        $keyType = 'FFF'; // For a Key Block LMK (This field is ignored)
        $keyAt32 = $this->hsmBdkBlock;
        $ksnDescriptor = 'A05';
        $ksnAt20 = strtoupper($ksn);
        $iv = sprintf('%016X', 0);
        $messageLength = sprintf('%04X', strlen($encryptedText));
        $encryptedMessage = strtoupper($encryptedText);
        $endMessageDelimiter = '';
        $messageTrailer = '';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $commandCode .
            $modeFlag .
            $inputFormatFlag .
            $outputFormatFlag .
            $keyType .
            $keyAt32 .
            $ksnDescriptor .
            $ksnAt20 .
            $iv .
            $messageLength .
            $encryptedMessage .
            $endMessageDelimiter .
            $messageTrailer;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Generate MAC コマンド(GW)の生成
     *
     * @param string $macTargetData MAC算出対象データ
     * @param string $ksn KSN
     * @return string
     */
    public function generateCommandGenerateMac(string $macTargetData, string $ksn): string
    {
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'GW'; // Generate/Verify a MAC (3DES & AES DUKPT)
        $macMode = '5'; // Generate 4 byte MAC (4 leftmost bytes of MAC)
        $macMethod = '1'; // ANSI X9.19
        $keyAt32 = $this->hsmBdkBlock;
        $ksnDescriptor = 'A05';
        $ksnAt20 = strtoupper($ksn);

        $workLength = strlen($macTargetData);
        $workMessageData = $macTargetData;
        if ($workLength % 8 == 0) {
            $workMessageData .= chr(0);
            $workLength++;
        }
        $workLength = $workLength ? ceil($workLength / 8) * 8 : 8;
        // 8の倍数の領域に左詰、余ったらchr(0)で埋める
        $messageData = sprintf('%-' . "'" . chr(0) . $workLength . 's', $workMessageData);
        $messageLength = sprintf('%04d', strlen($messageData));

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $commandCode .
            $macMode .
            $macMethod .
            $keyAt32 .
            $ksnDescriptor .
            $ksnAt20 .
            $messageLength .
            $messageData;

        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Import a Public Key コマンド(EO)の生成
     *
     * @param string $publicKey 公開鍵（バイナリデータ）
     * @return string
     */
    public function generateCommandImportPublicKey(string $publicKey): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'EO'; // Import a Public Key
        $pubKeyEncoding = '02'; // DER形式
        $optVariantLMK = '~'; // not include
        $optKeyBlockLMKDelimiter = '#';
        $optKeyBlockLMKMode = 'N'; // No special restrictions apply.
        $optKeyBlockLMKKeyVersionNo = '00';
        $optKeyBlockLMKExportability = 'S'; // Sensitive
        $optKeyBlockLMKNumberOfOptionalBlock = '00';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $command .
            $pubKeyEncoding .
            $publicKey .
            $optVariantLMK .
            $optKeyBlockLMKDelimiter .
            $optKeyBlockLMKMode .
            $optKeyBlockLMKKeyVersionNo .
            $optKeyBlockLMKExportability .
            $optKeyBlockLMKNumberOfOptionalBlock;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Export Key under an RSA Public Key コマンド(GK)の生成
     *
     * @param string $pubKeyMac 公開鍵MAC（バイナリデータ）
     * @return string
     */
    public function generateCommandExportKeyUnderPublicKey(string $pubKeyMac): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'GK'; // Export Key under an RSA Public Key
        $encryptionIdentifier = '01'; // RSA
        $padModeIdentifier = '02'; // PKCS#1 v2.2 OAEP method (EME-OAEP-ENCODE)
        $maskGenerationFunction = '01'; // MGF1 as defined in PKCS#1 v2.2.
        $mgfHashFunction = '01'; // SHA-1
        $oaepEncodingParametersLength = '00'; // no Encoding Parameters
        $oaepEncodingParametersDelimiter = ';'; // OAEP Encoding Parameters Delimiter
        $keyType = 'FFFF'; // ignored
        $desKeyFlag = 'F'; // ignored
        $keyUnderLmkWithCheckValue = $this->hsmTmkBlock . $this->hsmTmkMac;
        $delimiter1 = ';';
        $keyBlockType = '02'; // Key Data Block Template
        $keyBlockTemplateLength = '0020'; // Length of Key Data Block data
        $keyBlockTemplate = '0000800000000000000000000000000000000000';
        $delimiter2 = ';';
        $keyOffset = '0004';
        $checkValueLength = '00';
        $checkValueOffset = '0000';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $command .
            $encryptionIdentifier .
            $padModeIdentifier .
            $maskGenerationFunction .
            $mgfHashFunction .
            $oaepEncodingParametersLength .
            $oaepEncodingParametersDelimiter .
            $keyType .
            $desKeyFlag .
            $keyUnderLmkWithCheckValue .
            $pubKeyMac .
            $delimiter1 .
            $keyBlockType .
            $keyBlockTemplateLength .
            $keyBlockTemplate .
            $delimiter2 .
            $keyOffset .
            $checkValueLength .
            $checkValueOffset;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Derive & Export a Key コマンド(A0, mode:B)の生成（TR-31形式）
     *
     * @param string $iksn IKSN（Initial Key Serial Number）
     * @return string
     */
    public function generateCommandDeriveAndExportKeyFormattedTR31(string $iksn): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'A0'; // Generate a Key
        $mode = 'B'; // Derive key and encrypt under ZMK (or TMK or Current BDK)
        $keyType = 'FFF'; // ignored
        $keySchemeLMK = 'S'; // not included in the authenticated data
        $deriveKeyMode = '0'; // DUKPT - Derive IKEY from DUKPT Master Key
        $dukptMasterKeyType = '1'; // BDK-1
        $dukptMasterKey = $this->hsmBdkBlock;
        $ksn = $iksn;
        $tmk = $this->hsmTmkBlock;
        $keySchemeTMK = 'R'; // TR-31 Key Block
        $delimiter = '#';
        $keyUsage = 'B1'; // DUKPT Initial Key, IKEY
        $algorithm = 'T2'; // double length DES key
        $modeOfUse = 'N'; // No special restrictions apply.
        $keyVersionNumber = '00';
        $exportability = 'S'; // Sensitive
        $numberOfOptionalBlocks = '00';
        // 以下バージョンB用追加パラメータ
        $delimiter2Tr31 = '&';
        $modifiedExportValue = 'N';
        $delimiter3Tr31 = '!';
        $keyBlockVersionIDTr31 = 'B';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $command .
            $mode .
            $keyType .
            $keySchemeLMK .
            $deriveKeyMode .
            $dukptMasterKeyType .
            $dukptMasterKey .
            $ksn .
            $tmk .
            $keySchemeTMK .
            $delimiter .
            $keyUsage .
            $algorithm .
            $modeOfUse .
            $keyVersionNumber .
            $exportability .
            $numberOfOptionalBlocks .
            // 以下バージョンB用追加パラメータ
            $delimiter2Tr31 .
            $modifiedExportValue .
            $delimiter3Tr31 .
            $keyBlockVersionIDTr31;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }
}
