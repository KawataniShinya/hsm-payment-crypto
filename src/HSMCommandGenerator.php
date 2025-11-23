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
}
