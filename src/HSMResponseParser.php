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

    /**
     * Derive IPEK 応答からIPEKを抽出
     * IPEKの形式は未定、後続処理でTR-34形式で出力する想定
     *
     * @param string $responseData レスポンスデータ
     * @return array{ipek: string, kcv: string} IPEKとKCV
     */
    public function parseResponseDeriveIPEK(string $responseData): array
    {
        // LMK鍵ブロックの長さを算出
        $lmkKeyBlockStart = self::IPEK_POS_KEY_LMK;
        $lmkKeyBlockLength = $this->calculateLmkKeyBlockLength($responseData, $lmkKeyBlockStart);

        // KCVの開始位置を算出
        $kcvStart = $lmkKeyBlockStart + $lmkKeyBlockLength;

        $ipek = substr($responseData, $lmkKeyBlockStart, $lmkKeyBlockLength);
        $kcv = substr($responseData, $kcvStart, self::KCV_LEN);
        return [
            'ipek' => $ipek,
            'kcv' => strtoupper($kcv)
        ];
    }

    /**
     * Export IPEK formatted TR-34 応答からIPEK(TR-34形式)、KCV、Signatureを抽出
     *
     * @param string $responseData レスポンスデータ
     * @return array{ipekTr34: string, kcv: string, signature: string} IPEK(TR-34形式、HEX文字列)、KCV(HEX文字列)、Signature(HEX文字列)
     */
    public function parseResponseExportIPEKformattedTR34(string $responseData): array
    {
        $pos = self::RESPONSE_CODE_START_INDEX + self::RESPONSE_CODE_LENGTH + self::ERROR_CODE_LENGTH; // ヘッダー + Response Code + Error Code の後 (12バイト目)

        $binPayload = substr($responseData, $pos);
        echo 'hexPayload:' . bin2hex($binPayload);

        // 2Byte目: 1Byte目(タグ)はスキップし、lengthに関するデータを解析。
        $lengthPos = 1;
        $binPayloadLen = strlen($binPayload);
        $lengthInfo = $this->parseBerLengthFromPayload($binPayload, $lengthPos, $binPayloadLen);
        $dataLength = $lengthInfo['dataLength'];
        $lengthBytes = $lengthInfo['lengthBytes'];

        // Authenticated Attributesの終端位置を算出
        // タグ(1バイト) + lengthフィールド($lengthBytesバイト) + データ($dataLengthバイト)
        $authenticatedAttributesEndPos = 1 + $lengthBytes + $dataLength;

        // Authenticated Attributes以降のバイナリデータ（KCV、Enveloped Data、Signature Length、Signatureを含む）
        $binAfterAuthenticatedAttributes = substr($binPayload, $authenticatedAttributesEndPos);

        // KCVを取得（固定長3バイト）
        $kcv = bin2hex(substr($binAfterAuthenticatedAttributes, 0, 3));

        // Enveloped Data以降のバイナリデータを取得
        $binAfterKCV = substr($binAfterAuthenticatedAttributes, 3);

        // 2Byte目: lengthに関するデータを解析
        $envelopedDataLengthPos = 1;
        $binAfterKCVLen = strlen($binAfterKCV);
        $envelopedDataLengthInfo = $this->parseBerLengthFromPayload($binAfterKCV, $envelopedDataLengthPos, $binAfterKCVLen);
        $envelopedDataLength = $envelopedDataLengthInfo['dataLength'];
        $envelopedDataLengthBytes = $envelopedDataLengthInfo['lengthBytes'];

        // IPEK(TR-34)を抽出
        // タグとlengthフィールドの後、$envelopedDataLengthバイト分がIPEK(TR-34)
        $ipekTr34StartPos = 1 + $envelopedDataLengthBytes;
        $ipekTr34 = substr($binAfterKCV, $ipekTr34StartPos, $envelopedDataLength);
        $ipekTr34Hex = bin2hex($ipekTr34);

        // Enveloped Dataの終端位置を算出
        // タグ(1バイト) + lengthフィールド($envelopedDataLengthBytesバイト) + データ($envelopedDataLengthバイト)
        $envelopedDataEndPos = 1 + $envelopedDataLengthBytes + $envelopedDataLength;

        // それ以降のバイナリ（Signature Length、Signature）を取得
        $binAfterEnvelopedData = substr($binAfterKCV, $envelopedDataEndPos);

        // Signature Lengthを取得（最初の4バイト）
        $signatureLengthBytes = substr($binAfterEnvelopedData, 0, 4);
        $signatureLengthHex = bin2hex($signatureLengthBytes);

        // HEX文字列をASCII文字列として解釈（例：30323536 → "0256"）
        $signatureLengthStr = '';
        for ($i = 0; $i < strlen($signatureLengthHex); $i += 2) {
            $hexByte = substr($signatureLengthHex, $i, 2);
            $signatureLengthStr .= chr(hexdec($hexByte));
        }

        // ASCII文字列を整数として解釈（例："0256" → 256）
        $signatureLength = (int)$signatureLengthStr;

        // Signature Lengthの後、$signatureLengthバイト分がSignature
        $binAfterEnvelopedDataLen = strlen($binAfterEnvelopedData);
        if (4 + $signatureLength > $binAfterEnvelopedDataLen) {
            throw new Exception("binAfterEnvelopedData too short for Signature. required=" . (4 + $signatureLength) . ", actual=$binAfterEnvelopedDataLen");
        }

        // Signatureを抽出
        $signature = substr($binAfterEnvelopedData, 4, $signatureLength);
        $signatureHex = bin2hex($signature);

        return [
            'ipekTr34' => strtoupper($ipekTr34Hex),
            'kcv' => strtoupper($kcv),
            'signature' => strtoupper($signatureHex)
        ];
    }

    /**
     * BERエンコードされた長さフィールドを解析（hexPayload用）
     *
     * @param string $hexPayload バイナリデータ
     * @param int $pos lengthフィールドの開始位置
     * @param int $hexPayloadLen hexPayloadの長さ
     * @return array{dataLength: int, lengthBytes: int} データ長とlengthフィールド自体のバイト数
     */
    private function parseBerLengthFromPayload(string $hexPayload, int $pos, int $hexPayloadLen): array
    {
        if ($pos >= $hexPayloadLen) {
            throw new Exception("hexPayload too short for length field. pos=$pos, hexPayloadLen=$hexPayloadLen");
        }

        // lengthに関するデータ
        $lengthByte = ord($hexPayload[$pos]);
        $pos++;

        // 先頭ビットをチェック
        if (($lengthByte & 0x80) === 0) {
            // 短形式: 下7ビットがそのまま長さ値
            $dataLength = $lengthByte & 0x7F;
            $lengthBytes = 1; // lengthフィールド自体のバイト数
        } else {
            // 長形式: 下7ビットが後続の長さバイト数
            $lengthBytesCount = $lengthByte & 0x7F;

            if ($lengthBytesCount === 0 || $lengthBytesCount > 4) {
                throw new Exception("Invalid BER length format. lengthBytesCount=$lengthBytesCount");
            }

            if ($pos + $lengthBytesCount > $hexPayloadLen) {
                throw new Exception("hexPayload too short for long form length. pos=$pos, lengthBytesCount=$lengthBytesCount, hexPayloadLen=$hexPayloadLen");
            }

            // 後続Byteで長さが定義される
            $dataLength = 0;
            for ($i = 0; $i < $lengthBytesCount; $i++) {
                $dataLength = ($dataLength << 8) | ord($hexPayload[$pos + $i]);
            }

            $lengthBytes = 1 + $lengthBytesCount; // lengthフィールド自体のバイト数（1バイト目 + 後続バイト）
        }

        return [
            'dataLength' => $dataLength,
            'lengthBytes' => $lengthBytes
        ];
    }
}
