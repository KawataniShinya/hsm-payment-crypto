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

    /**
     * Derive IPEK コマンドの生成
     * IPEKを生成するためのコマンド（Key Block LMKで暗号化されたIPEKを導出）
     *
     * @param string $iksn IKSN
     * @return string
     */
    public function generateCommandDeriveIPEK(string $iksn): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'A0'; // Generate a Key
        $mode = 'A'; // Derive key
        $keyType = 'FFF'; // ignored
        $keySchemeLMK = 'S'; // not included in the authenticated data
        $deriveKeyMode = '0'; // DUKPT - Derive IKEY from DUKPT Master Key
        $dukptMasterKeyType = '1'; // BDK-1
        $dukptMasterKey = $this->hsmBdkBlock;
        $ksn = $iksn;
        $delimiter = '#';
        $keyUsage = 'B1'; // DUKPT Initial Key, IKEY
        $algorithm = 'T2'; // double length DES key
        $modeOfUse = 'N'; // No special restrictions apply.
        $keyVersionNumber = '00';
        $exportability = 'S'; // Sensitive
        $numberOfOptionalBlocks = '00';

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
            $delimiter .
            $keyUsage .
            $algorithm .
            $modeOfUse .
            $keyVersionNumber .
            $exportability .
            $numberOfOptionalBlocks .
            ''
        ;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Export IPEK formatted TR-34 コマンドの生成
     * IPEKをTR-34形式でエクスポートするためのコマンド
     *
     * @param string $ipek IPEK（形式未定、DeriveIPEK.phpで生成されたIPEK）
     * @param string $publicKey 公開鍵（バイナリデータ）
     * @return string
     */
    public function generateCommandExportIPEKformattedTR34(string $ipek, string $publicKey): string
    {
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'B8'; // TR-34 Key Export
        $schema = '0'; // X9 TR-34:2019 (Enveloped Data hash excludes sequence tag & length fields)
        $keyType = 'FFF';
        $key = strtoupper($ipek);
        $kdhCredential = pack('H*', '3045302d3110300e06035504030c075445535420434131193017060355040a0c10546865204f7267616e697a6174696f6e0214394e761ce65d48daf6dca240fd4f6a3fd35da110'); // KDHを一意に識別するために使用されるBERエンコードされた識別名とシリアル。
        $keyBlockEncryptionAlgorithm = '00'; // 192-bit TDES key – CBC
        $ephemeralKeyEncryptionAlgorithm = '00'; // RSA OAEP
        $numberOfKrdRecipients = '01';
        $krdCredential = pack('H*', '30818d3079310b3009060355040613024a5031153013060355040a0c0c4578616d706c6520436f727031193017060355040b0c105061796d656e74205365637572697479310e300c06035504080c05546f6b796f3110300e06035504070c07436869796f64613116301406035504030c0d4b44482049737375657220303102103a9fb24c11de77889900aa5566778890');
        $krdPublicKey = $publicKey;
        $oaepEncodingParametersLength = '00';
        $privateKeyFlag = '99'; // use private key provided with command.
        $kdhPrivateKeyLength = 'FFFF';
        $kdhPrivateKey = pack('H*', '5331303730343033525330304e303030307dbad43f8c8b4697452603068a204e8f8c2eafcfaa760e27948d1e5a92756d8c23a8437d4eb44238343b847d2588fdcaaa3d4b5c60d173410bb76aed3c40a1f102e9fdde153810616ae85fb6e9babaf84b071ea217cbab4865f84e70287eca4b4784e25a440de04cae2c226fa5ac1d7c20c8cd56b340af2bbc6061e350ee99a41429d57f9c31be9a174144d6f6f36387ea30e54ca2f6e407f2135828edc5a4d710c1589976e69594765e055243a1639c71ee0f8511d8650bb7d6f482a7133a8599326d72893d7023f3f3e5de9e92ffeadb3ca062b64027582ceb64c79958e89699f4f29ce0245df720018070dbc4cc94d96fe3ebffb67475624927f0839a1fbd50668075a9c40bfa3eca3999954b5cb4f4f0b944760c75f21c9d0485f2962c4ef09a298b4a41d3bda4d64833d66ba407f59d0b840cdcb0a4b52a8d2127e6e2472059235ac914259852469630b702957a1515673bd8fa0a7eb93252f08f5389a84e930aa101178b42ea95a74ee47e50ac4489d7e5c0ee41646888aaaf06ff7fad7e8e8729df9053c24059272c2ed0db8475ce47b373d343d819d81c5d678788b0932929dfd6fd722dc87ea3d23aeab82a42f4b1ef447716e945c562c42c2057b75d42d8934f27a686abb421d0f0eb17b947dcde54184f11372b3ce8bca1e8d6867a75d23e409c5345dcf81d27314b90d95e4cdc4935c229f1f701c1f546158b7485d740f7178c7cc946792b8bdb7823943ccd1b94c19aecfac737b8105b0b05c4643b9d5f6b392f8747880f8abe137cdb36fc505f8dea9c1200a16f3aa10e2cab4c0c4060377b1f5c97cd88328ca0f8bc814bcf3f3c511da2008a454dd70a08ad5be61c9d99f0ddb2b59f37c2c77bd59dc9c4c1ceb39dca2969e30ba9b80fcfea31a4af2a3c7d4bd5546b90e9d426fa9c20fddec74b06276412d213803af424ef32384530333438453446314137433745');
        $signedDataPadMode = '01'; // PKCS#1 V1.5
        $signedDataDigestAlgorithm = '0'; // SHA 256
        $randomNonceLength = '08';
        $randomNonce = pack('H*', 'ABCDABCDABCDABCD');
        $delimiter1Tr31 = '&';
        $modifiedExportValue = 'N';
        $delimiter2Tr31 = '!';
        $keyBlockVersionIDTr31 = 'B';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $command .
            $schema .
            $keyType .
            $key .
            $kdhCredential .
            $keyBlockEncryptionAlgorithm .
            $ephemeralKeyEncryptionAlgorithm .
            $numberOfKrdRecipients .
            $krdCredential .
            $krdPublicKey .
            $oaepEncodingParametersLength .
            $privateKeyFlag .
            $kdhPrivateKeyLength .
            $kdhPrivateKey .
            $signedDataPadMode .
            $signedDataDigestAlgorithm .
            $randomNonceLength .
            $randomNonce .
            $delimiter1Tr31 .
            $modifiedExportValue .
            $delimiter2Tr31 .
            $keyBlockVersionIDTr31 .
            ''
        ;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Form Key from Encrypted Components コマンド(A4)の生成
     *
     * @param string $keyComponent1 キーコンポーネント1
     * @param string $keyComponent2 キーコンポーネント2
     * @return string
     */
    public function generateCommandFormKeyFromEncryptedComponents(string $keyComponent1, string $keyComponent2): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'A4'; // Form Key from Encrypted Components
        $numberOfComponents = sprintf('%01d', 2); // コンポーネント数
        $keyType = 'FFF'; // For a Key Block LMK (This field is ignored)
        $keySchemeLMK = 'S'; // not included in the authenticated data
        $delimiter = '%';
        $lmkIdentifier = sprintf('%02d', 0);

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $commandCode .
            $numberOfComponents .
            $keyType .
            $keySchemeLMK .
            $keyComponent1 .
            $keyComponent2 .
            $delimiter .
            $lmkIdentifier;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Translate a PIN from BDK to BDK or ZPK Encryption (3DES & AES DUKPT) コマンド(G0)の生成
     *
     * @param string $zpk           ZPK
     * @param string $ksn           KSN
     * @param string $pinBlock      暗号化PIN BLOCK
     * @param string $accountNumber アカウント番号 (MSの場合は000000000000固定)
     * @return string
     */
    public function generateCommandTranslatePinFromEncryption(string $zpk, string $ksn, string $pinBlock, string $accountNumber): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'G0'; // Translate a PIN from BDK to BDK or ZPK Encryption
        $bdkAt32H = $this->hsmBdkBlock;
        $zpkAt32H = strtoupper($zpk);
        $ksnDescriptor = 'A05';
        $destinationKsn = strtoupper($ksn);
        $sourcePinBlock = strtoupper($pinBlock);
        $SourcePINBlockFormatCode = '01';
        $destinationPINBlockFormatCode = '01';
        $primaryAccountNumber = $accountNumber;
        $delimiter = '%';
        $lmkIdentifier = sprintf('%02d', 0);

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $commandCode .
            $bdkAt32H .
            $zpkAt32H .
            $ksnDescriptor .
            $destinationKsn .
            $sourcePinBlock .
            $SourcePINBlockFormatCode .
            $destinationPINBlockFormatCode .
            $primaryAccountNumber .
            $delimiter .
            $lmkIdentifier;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Decrypt Data Block コマンド(M2, ECB)の生成
     * 復号化キーを使用したECBモードでの復号化コマンド
     *
     * @param string $pinBlock PIN Block（16進数文字列）
     * @param string $decryptKey 復号化キー（TR-31形式のキーブロック）
     * @return string
     */
    public function generateCommandDecryptDataBlockWithECB(string $pinBlock, string $decryptKey): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'M2'; // Decrypt Data Block
        $modeFlag = sprintf('%02d', 0); // ECB
        $inputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $outputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $keyType = 'FFF'; // For a Key Block LMK (This field is ignored)
        $keyAt32 = strtoupper($decryptKey);
        $messageLength = sprintf('%04X', strlen($pinBlock));
        $encryptedMessage = strtoupper($pinBlock);
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
            $messageLength .
            $encryptedMessage .
            $endMessageDelimiter .
            $messageTrailer;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Decrypt Data Block コマンド(M2, ECB with BDK)の生成
     * BDKを使用したECBモードでの復号化コマンド
     *
     * @param string $encryptedText 暗号化文字列
     * @param string $ksn           KSN
     *
     * @return string
     */
    public function generateCommandDecryptDataBlockWithECBWithBDK(string $encryptedText, string $ksn): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $commandCode = 'M2'; // Decrypt Data Block
        $modeFlag = sprintf('%02d', 0); // ECB
        $inputFormatFlag = sprintf('%01d', 1); // Hex-Encoded Binary
        $outputFormatFlag = sprintf('%01d', 0); // Binary
        $keyType = 'FFF'; // For a Key Block LMK (This field is ignored)
        $keyAt32 = $this->hsmBdkBlock;
        $ksnDescriptor = 'A05';
        $ksnAt20 = strtoupper($ksn);
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
            $messageLength .
            $encryptedMessage .
            $endMessageDelimiter .
            $messageTrailer;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }

    /**
     * Generate Key コマンド(A0)の生成
     * TMK生成用のコマンド
     *
     * @return string
     */
    public function generateCommandGenerateKey(): string
    {
        // パラメータ設定（整形済み）
        $header = '00001'; // カウンター(固定)
        $headerBodySeparator = '-';
        $command = 'A0'; // Generate a Key
        $mode = '0'; // Generate key
        $keyType = 'FFF'; // ignored
        $keySchemeLMK = 'S'; // not included in the authenticated data
        $fieldDelimiter = '%';
        $lmkIdentifier = '00';
        $sectionDelimiter = '#';
        $keyUsage = '51'; // Terminal key encryption, TMK
        $algorithm = 'T2'; // double length DES key
        $modeOfUse = 'N'; // No special restrictions apply.
        $keyVersionNumber = '00';
        $exportability = 'S'; // Sensitive
        $numberOfOptionalBlocks = '00';

        // ペイロード作成
        $telegram =
            $header .
            $headerBodySeparator .
            $command .
            $mode .
            $keyType .
            $keySchemeLMK .
            $fieldDelimiter .
            $lmkIdentifier .
            $sectionDelimiter .
            $keyUsage .
            $algorithm .
            $modeOfUse .
            $keyVersionNumber .
            $exportability .
            $numberOfOptionalBlocks;

        // メッセージ生成（長さ + ペイロード）
        $message = pack('H*', sprintf('%04X', strlen($telegram))) . $telegram;

        return $message;
    }
}
