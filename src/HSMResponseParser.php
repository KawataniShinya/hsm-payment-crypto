<?php

/**
 * HSM応答解析クラス
 */

class HSMResponseParser
{
    public const ERROR_CODE_NO_ERROR = '00'; // 応答正常

    private const INITIAL_CONTROL_CHAR_SIZE = 2; // 先頭制御文字の長さ
    private const RESPONSE_CODE_START_INDEX = 8; // 応答コードの開始位置
    private const RESPONSE_CODE_LENGTH = 2; // 応答コードの長さ
    private const ERROR_CODE_START_INDEX = 10; // エラーコードの開始位置
    private const ERROR_CODE_LENGTH = 2; // エラーコードの長さ
    private const OFFSET_PUBLIC_KEY_MAC = 12; // 公開鍵インポート結果におけるMAC値格納位置
    private const IPEK_POS_KEY_LMK = 12; // LMK開始位置 : ヘッダー開始(1) + 区切り文字(1) + ヘッダー(6) + 応答コード(2) + エラーコード(2)
    private const KCV_LEN = 6; // Key Check Value 長

    /**
     * Encrypt Data Block 応答(M1)から結果を抽出
     *
     * @param string $responseData
     *
     * @return string 暗号化文字列
     */
    public function parseResponseEncryptDataBlock(string $responseData): string
    {
        // 結果取得
        $resultHex = substr(bin2hex($responseData), 64);

        return $resultHex;
    }

    /**
     * 応答コードを取得
     *
     * @param string $responseData
     *
     * @return string
     */
    public function getResponseCode(string $responseData): string
    {
        return substr($responseData, self::RESPONSE_CODE_START_INDEX, self::RESPONSE_CODE_LENGTH);
    }

    /**
     * 応答よりエラーコードを取得
     *
     * @param string $responseData
     *
     * @return string
     */
    public function getErrorCode(string $responseData): string
    {
        return substr($responseData, self::ERROR_CODE_START_INDEX, self::ERROR_CODE_LENGTH);
    }

    /**
     * HSM応答からテキスト表示可能な文字列を抽出
     *
     * @param string $responseMessage
     *
     * @return string
     */
    public function getPayloadWithoutBinary(string $responseMessage): string
    {
        // 制御文字の部分をカット
        $payload = substr($responseMessage, self::INITIAL_CONTROL_CHAR_SIZE);

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
     * 復号化レスポンスを解析して16進数文字列として返す
     *
     * @param string $responseData レスポンスデータ
     * @return string 復号化された16進数文字列
     */
    public function parseResponseDecryptDataBlockWithIvToHex(string $responseData): string
    {
        $resultHex = substr(bin2hex($responseData), 64);
        return $resultHex;
    }

    /**
     * MAC生成レスポンスを解析してMAC文字列として返す
     *
     * @param string $responseData レスポンスデータ
     * @return string MAC文字列
     */
    public function parseResponseGenerateMAC(string $responseData): string
    {
        $responseCode = substr($responseData, 12, 8);
        return $responseCode;
    }

    /**
     * Import a Public Key 応答(EP)から公開鍵MACを抽出
     *
     * @param string $responseData レスポンスデータ
     * @return string 公開鍵MAC（バイナリデータ）
     */
    public function parseResponseImportPublicKey(string $responseData): string
    {
        return substr($responseData, self::OFFSET_PUBLIC_KEY_MAC);
    }

    /**
     * Export Key under an RSA Public Key 応答(GL)から結果を抽出
     *
     * @param string $responseData レスポンスデータ
     * @return string 暗号化TMK（Base64エンコード）
     */
    public function parseResponseExportKeyUnderPublicKey(string $responseData): string
    {
        $encryptedTmk = substr($responseData, 16);
        $encryptedTmkBase64Encoded = base64_encode($encryptedTmk);
        return $encryptedTmkBase64Encoded;
    }

    /**
     * Derive & Export a Key 応答(A0, mode:B)からIPEKとKCVを抽出（TR-31形式）
     *
     * @param string $responseData レスポンスデータ
     * @return array{ipekTr31: string, kcv: string} IPEK(TR-31形式)とKCV
     */
    public function parseResponseDeriveAndExportKeyFormattedTR31(string $responseData): array
    {
        // LMK鍵ブロックの長さを算出
        $lmkKeyBlockStart = self::IPEK_POS_KEY_LMK;
        $lmkKeyBlockLength = $this->calculateLmkKeyBlockLength($responseData, $lmkKeyBlockStart);

        // TR-31鍵ブロックの開始位置と長さを算出
        $tr31KeyBlockStart = $lmkKeyBlockStart + $lmkKeyBlockLength;
        $tr31KeyBlockLength = $this->calculateTr31KeyBlockLength($responseData, $tr31KeyBlockStart);

        // KCVの開始位置を算出
        $kcvStart = $tr31KeyBlockStart + $tr31KeyBlockLength;

        $ipekTr31 = substr($responseData, $tr31KeyBlockStart, $tr31KeyBlockLength);
        // KCVはASCII文字列として6文字の16進数で含まれる
        $kcv = substr($responseData, $kcvStart, self::KCV_LEN);
        return [
            'ipekTr31' => $ipekTr31,
            'kcv' => strtoupper($kcv)
        ];
    }

    /**
     * LMK鍵ブロックから長さを算出
     * フォーマット: S + バージョンID(1文字) + 合計長(4文字) + ...
     * 合計長はスキーム識別子を除いた鍵の長さを示す
     *
     * @param string $responseData
     * @param int $startPosition LMK鍵ブロックの開始位置
     *
     * @return int LMK鍵ブロックの実際の長さ（スキーム識別子を含む）
     */
    private function calculateLmkKeyBlockLength(string $responseData, int $startPosition): int
    {
        // スキーム識別子が'S'であることを確認
        if (substr($responseData, $startPosition, 1) !== 'S') {
            throw new Exception('Invalid LMK key block: expected scheme identifier "S"');
        }

        // 3桁目から4桁分（位置2-5、0-indexedでは位置2-5）を取得して合計長を算出
        $totalLengthStr = substr($responseData, $startPosition + 2, 4);
        $totalLength = (int) $totalLengthStr;

        // 実際の鍵ブロック全文の長さ = スキーム識別子(1文字) + 合計長
        return 1 + $totalLength;
    }

    /**
     * TR-31鍵ブロックから長さを算出
     * フォーマット: R + バージョンID(1文字) + キーブロック長(4文字) + ...
     * キーブロック長はキー・スキーム識別子を除いた鍵の長さを示す
     *
     * @param string $responseData
     * @param int $startPosition TR-31鍵ブロックの開始位置
     *
     * @return int TR-31鍵ブロックの実際の長さ（キー・スキーム識別子を含む）
     */
    private function calculateTr31KeyBlockLength(string $responseData, int $startPosition): int
    {
        // キー・スキーム識別子が'R'であることを確認
        if (substr($responseData, $startPosition, 1) !== 'R') {
            throw new Exception('Invalid TR-31 key block: expected key scheme identifier "R"');
        }

        // 3桁目から4桁分（位置2-5、0-indexedでは位置2-5）を取得してキーブロック長を算出
        $keyBlockLengthStr = substr($responseData, $startPosition + 2, 4);
        $keyBlockLength = (int) $keyBlockLengthStr;

        // 実際の鍵ブロック全文の長さ = キー・スキーム識別子(1文字) + キーブロック長
        return 1 + $keyBlockLength;
    }
}
