<?php

/**
 * PIN復号化ユーティリティクラス
 * DUKPT復号化PINデータとPANからPINを取得する処理を提供
 */
class PINUtil
{
    /**
     * DUKPT復号化PINデータとPANからPINを取得
     *
     * @param string $dukptDecryptedPinData DUKPT復号化PINデータ（16進数文字列）
     * @param string|null $pan PAN（Primary Account Number、オプション）
     * @return string PIN（数字文字列）
     * @throws InvalidArgumentException
     */
    public static function extractPINFromDecryptedData(string $dukptDecryptedPinData, ?string $pan = null): string
    {
        // メッセージ長を取得（最初の4文字、16進数）
        if (strlen($dukptDecryptedPinData) < 4) {
            throw new InvalidArgumentException("DUKPT復号化PINデータが短すぎます（最小4文字必要）");
        }

        $mesLen = hexdec(substr($dukptDecryptedPinData, 0, 4)); // Message Length （16進数）

        // PIN Block DUKを取得
        if (strlen($dukptDecryptedPinData) < 4 + $mesLen) {
            throw new InvalidArgumentException("DUKPT復号化PINデータが短すぎます（メッセージ長が不正）");
        }

        $pinBlockDuk = substr($dukptDecryptedPinData, 4, $mesLen); // Decrypted Message

        // PINの桁数を取得（PIN Block DUKの最初の2文字、16進数）
        if (strlen($pinBlockDuk) < 2) {
            throw new InvalidArgumentException("PIN Block DUKが短すぎます（最小2文字必要）");
        }

        $pinLen = hexdec(substr($pinBlockDuk, 0, 2)); // 暗証番号の桁数

        // アカウント番号を生成
        $accountNumber = str_repeat('0', 16); // デフォルトは16文字の'0'

        if ($pan) {
            // チェックデジット削除
            $number = substr($pan, 0, strlen($pan) - 1);
            // '0000' + 後ろから12桁
            $accountNumber = '0000' . substr($number, -12);
        }

        // 16進数を10進数に変換する->XOR->10進数を16進数に変換する
        $pin = dechex(hexdec($accountNumber) ^ hexdec($pinBlockDuk));

        // 頭の0が落ちるのでつける、$pinの長さが$mesLenになるまで先頭に0を追加
        $pin = str_pad($pin, $mesLen, '0', STR_PAD_LEFT);

        // 長さの領域を取り除く（最初の2文字）
        $pin = substr($pin, 2, $pinLen);

        return $pin;
    }
}
