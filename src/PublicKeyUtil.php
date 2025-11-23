<?php

/**
 * 公開鍵ユーティリティクラス
 * X.509形式のBase64エンコードされた公開鍵から実際の公開鍵を抽出
 */

class PublicKeyUtil
{
    public const PUBLIC_KEY_OBJECT_ID = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    /**
     * X.509形式のBase64エンコードされた公開鍵から実際の公開鍵を抽出
     *
     * @param string $base64Key Base64エンコードされた公開鍵
     * @return string 抽出された公開鍵（バイナリデータ）
     * @throws InvalidArgumentException
     */
    public static function getPublicKeyFromX509Base64(string $base64Key): string
    {
        // Base64デコード
        $bytes = base64_decode($base64Key, true);
        if ($bytes === false) {
            throw new InvalidArgumentException("Invalid Base64 encoded public key");
        }
        $count = strlen($bytes);
        $pos = 0;

        $search = 0x06; // PUBLIC_KEY_ID
        while ($pos < $count) {
            $tagInfo = self::readDerTag($bytes, $pos);
            if ($tagInfo === null) {
                throw new InvalidArgumentException("Invalid DER format");
            }

            [$tag, $dataLen, $pos] = $tagInfo;

            // 期待するタグを順番に探索し、公開鍵のIDが含まれているBIT STRINGを見つけ、そのデータを取り出す。
            if ($tag === 0x30 || $tag === 0x31) { // ID_SEQUENCE or ID_SET
                // データコンテナであるSEQUENCEやSETでは内部にさらにタグ付きのデータがあるため、次のデータの開始位置に直接移動。
                $pos = $tagInfo[2];
            } elseif ($search === 0x06 && $tag === 0x06) { // ID_OBJECT_ID
                if (self::isObjectId($bytes, $pos)) {
                    $search = 0x03; // PUBLIC_KEY
                }
                $pos += $dataLen;
            } elseif ($search === 0x03 && $tag === 0x03) { // ID_BIT_STRING
                $datLen = $dataLen - 1;
                $datPos = $pos + 1;
                $key = substr($bytes, $datPos, $datLen);

                return $key;
            } else {
                $pos += $dataLen;
            }
        }

        throw new InvalidArgumentException("Public key not found in X.509 format");
    }

    /**
     * DER形式タグ読み取り
     *
     * @param string $bytes バイト列（DER形式）
     * @param int $pos 現在の解析位置（バイトオフセット）
     * @return array{0: int, 1: int, 2: int}|null タグの種類、データの長さ、次のタグの位置
     */
    private static function readDerTag(string $bytes, int $pos): ?array
    {
        if ($pos >= strlen($bytes)) {
            return null;
        }
        $tag = ord($bytes[$pos++]);
        if ($pos >= strlen($bytes)) {
            return null;
        }
        $len = ord($bytes[$pos++]);
        $datLen = 0;

        // DERフォーマットでは、長さフィールドは1バイトまたは複数バイトでエンコードされている
        if ($len > 127) {
            $lenSize = $len - 128;
            if ($lenSize > 4 || $lenSize === 0) {
                return null;
            }
            for ($i = 1; $i <= $lenSize; $i++) {
                if ($pos >= strlen($bytes)) {
                    return null;
                }
                $datLen += (pow(256, ($lenSize - $i)) * ord($bytes[$pos++]));
            }
        } else {
            $datLen = $len;
        }

        return [$tag, $datLen, $pos];
    }

    /**
     * 指定されたバイト列内のデータが公開鍵の形式であることを確認
     *
     * @param string $bytes バイト列
     * @param int $pos バイト列内でオブジェクトIDの検索を開始する位置
     * @return bool オブジェクトIDが一致する場合は true
     */
    private static function isObjectId(string $bytes, int $pos): bool
    {
        $objectId = self::PUBLIC_KEY_OBJECT_ID;
        for ($i = 0; $i < count($objectId); $i++) {
            if ($pos + $i >= strlen($bytes) || ord($bytes[$pos + $i]) !== $objectId[$i]) {
                return false;
            }
        }

        return true;
    }
}
