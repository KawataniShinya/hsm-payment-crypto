<?php

/**
 * 16進数文字列とバイナリデータの変換ユーティリティクラス
 */

class HexUtil
{
    /**
     * 16進数文字列を2桁ずつ分割し、それぞれを文字に変換する。
     *
     * @param string $hexString
     *
     * @return string
     */
    public static function convertHexToString(string $hexString): string
    {
        $resultText = '';
        for ($i = 0; $i < strlen($hexString); $i += 2) {
            // 2桁ずつ取り出して16進数を10進数に変換
            $decimal = hexdec(substr($hexString, $i, 2));

            // 10進数を文字に変換して連結
            $resultText .= chr($decimal);
        }

        return $resultText;
    }

    /**
     * 16進数文字列を2桁ずつ分割し、それぞれを文字に変換する。
     * 終端を0x80とする。
     *
     * @param string $hexString
     *
     * @return string
     */
    public static function convertHexToStringUntil80(string $hexString): string
    {
        $charArray = [];
        for ($i = 0; $i < strlen($hexString); $i += 2) {
            // 2桁ずつ取り出して16進数をバイナリデータに変換
            $hexPair = substr($hexString, $i, 2);

            // '80'に達したら処理を終了
            if (strtoupper($hexPair) === '80') {
                break;
            }

            // 16進数を10進数に変換してから文字に変換
            $char = chr(hexdec($hexPair));
            $charArray[] = $char;
        }

        // 結果の文字列を結合する
        $resultText = implode('', $charArray);

        return $resultText;
    }

    /**
     * XORチェックサムを算出する
     * 指定された16進数文字列の各バイトをXOR演算して結果を返す
     *
     * @param string $hexString 16進数文字列（偶数桁である必要があります）
     *
     * @return string XOR結果の16進数文字列（2桁）
     */
    public static function calculateXorChecksum(string $hexString): string
    {
        // 入力チェック
        if (strlen($hexString) % 2 !== 0) {
            throw new InvalidArgumentException('入力の16進数文字列は偶数桁である必要があります。');
        }

        $xor = 0x00;

        // 2桁ずつ取り出してXOR演算
        for ($i = 0; $i < strlen($hexString); $i += 2) {
            $hexPair = substr($hexString, $i, 2);
            $byte = hexdec($hexPair);
            $xor ^= $byte;
        }

        // 結果を2桁の16進数文字列として返す
        return strtoupper(str_pad(dechex($xor), 2, '0', STR_PAD_LEFT));
    }
}
