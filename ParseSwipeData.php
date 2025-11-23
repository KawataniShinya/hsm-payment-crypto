<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/src/HSMClient.php';
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';
require_once __DIR__ . '/src/HexUtil.php';
require_once __DIR__ . '/src/EmvParser.php';
require_once __DIR__ . '/src/property.php';

/**
 * スワイプデータパーサー
 * GenerateSwipeData.phpの逆処理として、swipe_dataをパースするツール
 * IC処理とMS処理に対応
 */

// コマンドライン引数を取得
if ($argc !== 2) {
    echo "Usage: php ParseSwipeData.php <swipeData>\n";
    echo "  swipeData: パース対象のスワイプデータ（16進数文字列）\n";
    exit(1);
}

$swipeData = $argv[1];

try {
    // 16進数文字列をバイナリデータに変換
    $binaryData = pack('H*', $swipeData);

    // NUMフィールドでIC/MSを判別
    // STX(1Byte) + LEN0(2Byte) の後がNUMまたはKSN
    $numByte = ord($binaryData[3]); // STX(1) + LEN0(2) = 3バイト目
    $isMS = ($numByte === 0x05); // NUM=0x05ならMS

    if ($isMS) {
        // MS用のパース実行
        $parsedData = parseSwipeDataMS($binaryData);
        $parsedData['type'] = 'MS';

        // DATA1を復号化（KSNはASCII形式なので16進数に変換）
        $ksnHex = $parsedData['ksn']; // 既にbin2hexされている
        $decryptedData1 = decryptData1($parsedData['data1'], $ksnHex);
        $parsedData['decrypted_data1'] = $decryptedData1;

        // DATA1の内部構造をパース（磁気カードデータ）
        $parsedData['decrypted_data1_internal'] = parseMagneticCardData($decryptedData1);

        // DATA2をEMVパース（平文なのでそのままパース可能）
        $emvParsedData2 = EmvParser::parseEmvData($parsedData['data2']);
        $parsedData['emv_parsed_data2'] = $emvParsedData2;

        // DATA3 (JISII Track)をパース（DATA1内部構造に含まれる）
        if (isset($parsedData['decrypted_data1_internal']['data3_parsed']) && !empty($parsedData['decrypted_data1_internal']['data3_parsed'])) {
            // 既にparseMagneticCardData内でパース済み
        }
    } else {
        // IC用のパース実行
        $parsedData = parseSwipeDataIC($binaryData);
        $parsedData['type'] = 'IC';

        // DATA1を復号化
        $decryptedData1 = decryptData1($parsedData['data1'], $parsedData['ksn']);
        $parsedData['decrypted_data1'] = $decryptedData1;

        // DATA1をEMVパース
        $emvParsedData1 = EmvParser::parseEmvData($decryptedData1);
        $parsedData['emv_parsed_data1'] = $emvParsedData1;

        // DATA3をEMVパース（平文なのでそのままパース可能）
        $emvParsedData3 = EmvParser::parseEmvData($parsedData['data3']);
        $parsedData['emv_parsed_data3'] = $emvParsedData3;
    }

    // 結果出力
    echo PHP_EOL . "=== RESULT ===" . PHP_EOL;
    outputParsedData($parsedData);

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    exit(1);
}

/**
 * IC用スワイプデータをパースする
 *
 * @param string $binaryData バイナリデータ
 * @return array パースされたデータ
 * @throws Exception
 */
function parseSwipeDataIC(string $binaryData): array
{
    $offset = 0;
    $data = [];

    // 1. STX (1Byte)
    $data['stx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 2. LEN0 (2Byte) - 全体の長さ
    $len0Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len0'] = $len0Hex;
    $data['len0_value'] = hexdec($len0Hex);
    $offset += 2;

    // 3. KSN (10Byte)
    $data['ksn'] = bin2hex(substr($binaryData, $offset, 10));
    $offset += 10;

    // 4. 取引結果 (1Byte)
    $data['trans_result'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 5. LEN1 (2Byte) - カード情報暗号文の長さ
    $len1Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len1'] = $len1Hex;
    $data['len1_value'] = hexdec($len1Hex);
    $offset += 2;

    // 6. DATA1 (LEN1) - カード情報暗号文
    $data['data1'] = bin2hex(substr($binaryData, $offset, $data['len1_value']));
    $offset += $data['len1_value'];

    // 7. LEN2 (2Byte) - オンラインPIN暗号文の長さ
    $len2Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len2'] = $len2Hex;
    $data['len2_value'] = hexdec($len2Hex);
    $offset += 2;

    // 8. DATA2 (LEN2) - オンラインPIN暗号文
    $data['data2'] = bin2hex(substr($binaryData, $offset, $data['len2_value']));
    $offset += $data['len2_value'];

    // 9. LEN3 (2Byte) - カード情報平文長さ
    $len3Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len3'] = $len3Hex;
    $data['len3_value'] = hexdec($len3Hex);
    $offset += 2;

    // 10. DATA3 (LEN3) - カード情報平文
    $data['data3'] = bin2hex(substr($binaryData, $offset, $data['len3_value']));
    $offset += $data['len3_value'];

    // 11. LEN4 (2Byte) - MAC長さ
    $len4Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len4'] = $len4Hex;
    $data['len4_value'] = hexdec($len4Hex);
    $offset += 2;

    // 12. DATA4 (LEN4) - MAC
    $data['data4'] = bin2hex(substr($binaryData, $offset, $data['len4_value']));
    $offset += $data['len4_value'];

    // 13. XOR (1Byte)
    $data['xor'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 14. ETX (1Byte)
    $data['etx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    return $data;
}

/**
 * DATA1を復号化する
 *
 * @param string $encryptedData1 暗号化されたDATA1
 * @param string $ksn KSN
 * @return string 復号化された文字列
 * @throws Exception
 */
function decryptData1(string $encryptedData1, string $ksn): string
{
    try {
        // 設定を読み込み
        $config = require __DIR__ . '/src/property.php';

        // HSMクライアントを初期化
        $hsmClient = new HSMClient($config);

        // 復号化実行
        $decryptedText = $hsmClient->decryptDataBlockWithCBCToString($encryptedData1, $ksn);

        return $decryptedText;
    } catch (Exception $e) {
        return "復号化エラー: " . $e->getMessage();
    }
}

/**
 * MS用スワイプデータをパースする
 *
 * @param string $binaryData バイナリデータ
 * @return array パースされたデータ
 * @throws Exception
 */
function parseSwipeDataMS(string $binaryData): array
{
    $offset = 0;
    $data = [];

    // 1. STX (1Byte)
    $data['stx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 2. LEN0 (2Byte) - 全体の長さ
    $len0Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len0'] = $len0Hex;
    $data['len0_value'] = hexdec($len0Hex);
    $offset += 2;

    // 3. NUM (1Byte) - Data content Type 0x05
    $data['num'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 4. LEN1 (2Byte) - Encrypted Data Length
    $len1Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len1'] = $len1Hex;
    $data['len1_value'] = hexdec($len1Hex);
    $offset += 2;

    // 5. DATA1 (LEN1) - Encrypted Data
    $data['data1'] = bin2hex(substr($binaryData, $offset, $data['len1_value']));
    $offset += $data['len1_value'];

    // 6. LEN2 (2Byte) - Plain Data Length
    $len2Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len2'] = $len2Hex;
    $data['len2_value'] = hexdec($len2Hex);
    $offset += 2;

    // 7. DATA2 (LEN2) - Plain Data (EMV形式)
    $data['data2'] = bin2hex(substr($binaryData, $offset, $data['len2_value']));
    $offset += $data['len2_value'];

    // 8. LEN3 (2Byte) - KSN Length
    $len3Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len3'] = $len3Hex;
    $data['len3_value'] = hexdec($len3Hex);
    $offset += 2;

    // 9. DATA3 (LEN3) - KSN (ASCII)
    $ksnBinary = substr($binaryData, $offset, $data['len3_value']);
    $data['data3'] = bin2hex($ksnBinary);
    $data['ksn'] = bin2hex($ksnBinary); // KSNとしても保存
    $offset += $data['len3_value'];

    // 10. LEN4 (4Byte) - RI Length
    $len4Hex = bin2hex(substr($binaryData, $offset, 4));
    $data['len4'] = $len4Hex;
    $data['len4_value'] = hexdec($len4Hex);
    $offset += 4;

    // 11. DATA4 (LEN4) - RI
    $data['data4'] = bin2hex(substr($binaryData, $offset, $data['len4_value']));
    $offset += $data['len4_value'];

    // 12. LEN5 (2Byte) - MAC Length
    $len5Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len5'] = $len5Hex;
    $data['len5_value'] = hexdec($len5Hex);
    $offset += 2;

    // 13. DATA5 (LEN5) - MAC
    $data['data5'] = bin2hex(substr($binaryData, $offset, $data['len5_value']));
    $offset += $data['len5_value'];

    // 14. XOR (1Byte)
    $data['xor'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 15. ETX (1Byte)
    $data['etx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    return $data;
}

/**
 * 磁気カードデータ（DATA1復号化後の内部構造）をパースする
 *
 * @param string $decryptedData1 復号化されたDATA1（16進数文字列）
 * @return array パースされた磁気カードデータ
 */
function parseMagneticCardData(string $decryptedData1): array
{
    $binaryData = pack('H*', $decryptedData1);
    $offset = 0;
    $data = [];

    // 1. STX (1Byte)
    $data['stx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 2. LEN0 (2Byte) - Total length
    $len0Hex = bin2hex(substr($binaryData, $offset, 2));
    $data['len0'] = $len0Hex;
    $data['len0_value'] = hexdec($len0Hex);
    $offset += 2;

    // 3. LEN1 (1Byte) - JIS I ISO 1st Track Data Length
    $len1Hex = bin2hex(substr($binaryData, $offset, 1));
    $data['len1'] = $len1Hex;
    $data['len1_value'] = hexdec($len1Hex);
    $offset += 1;

    // 4. DATA1 (LEN1) - JIS I ISO 1st Track Data
    $data1Hex = bin2hex(substr($binaryData, $offset, $data['len1_value']));
    $data['data1'] = $data1Hex;
    if ($data['len1_value'] > 0) {
        $data['data1_parsed'] = parseJIS1FirstTrack($data1Hex);
    }
    $offset += $data['len1_value'];

    // 5. LEN2 (1Byte) - JIS I ISO 2nd Track Data Length
    $len2Hex = bin2hex(substr($binaryData, $offset, 1));
    $data['len2'] = $len2Hex;
    $data['len2_value'] = hexdec($len2Hex);
    $offset += 1;

    // 6. DATA2 (LEN2) - JIS I ISO 2nd Track Data
    $data2Hex = bin2hex(substr($binaryData, $offset, $data['len2_value']));
    $data['data2'] = $data2Hex;
    if ($data['len2_value'] > 0) {
        $data['data2_parsed'] = parseJIS1SecondTrack($data2Hex);
    }
    $offset += $data['len2_value'];

    // 7. LEN3 (1Byte) - JISII Track Data Length
    $len3Hex = bin2hex(substr($binaryData, $offset, 1));
    $data['len3'] = $len3Hex;
    $data['len3_value'] = hexdec($len3Hex);
    $offset += 1;

    // 8. DATA3 (LEN3) - JISII Track Data
    $data3Hex = bin2hex(substr($binaryData, $offset, $data['len3_value']));
    $data['data3'] = $data3Hex;
    if ($data['len3_value'] > 0) {
        $data['data3_parsed'] = parseJIS2Track($data3Hex);
    }
    $offset += $data['len3_value'];

    // 9. XOR (1Byte)
    $data['xor'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    // 10. ETX (1Byte)
    $data['etx'] = bin2hex(substr($binaryData, $offset, 1));
    $offset += 1;

    return $data;
}

/**
 * JIS1 1st Trackデータをパースする
 *
 * @param string $trackDataHex 1st Trackデータ（16進数文字列）
 * @return array パースされたデータ
 */
function parseJIS1FirstTrack(string $trackDataHex): array
{
    $trackData = pack('H*', $trackDataHex);
    $offset = 0;
    $data = [];

    // 1. STX (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['stx'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 2. Format Code (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['format_code'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 3. Member ship Number (13 or 16 digits) - セパレータ（^）まで読み取る（ASCII文字列のまま）
    $membershipNumber = '';
    while ($offset < strlen($trackData) && $trackData[$offset] !== '^') {
        $membershipNumber .= $trackData[$offset];
        $offset += 1;
    }
    $data['membership_number'] = $membershipNumber;
    $data['membership_number_hex'] = bin2hex($membershipNumber);

    // 4. Separator (1Byte) - ^ - 16進数文字列として出力
    if ($offset < strlen($trackData) && $trackData[$offset] === '^') {
        $data['separator1'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 5. Holder Name (2~26 digits) - セパレータ（^）まで読み取る（ASCII文字列のまま）
    $holderName = '';
    while ($offset < strlen($trackData) && $trackData[$offset] !== '^') {
        $holderName .= $trackData[$offset];
        $offset += 1;
    }
    $data['holder_name'] = $holderName;
    $data['holder_name_hex'] = bin2hex($holderName);

    // 6. Separator (1Byte) - ^ - 16進数文字列として出力
    if ($offset < strlen($trackData) && $trackData[$offset] === '^') {
        $data['separator2'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 7. Expire Date (4 digits) - ASCII文字列のまま
    if ($offset + 4 <= strlen($trackData)) {
        $data['expire_date'] = substr($trackData, $offset, 4);
        $offset += 4;
    }

    // 8. Service Code (3 digits) - ASCII文字列のまま
    if ($offset + 3 <= strlen($trackData)) {
        $data['service_code'] = substr($trackData, $offset, 3);
        $offset += 3;
    }

    // 9. PIN Code (5 digits) - ASCII文字列のまま
    if ($offset + 5 <= strlen($trackData)) {
        $data['pin_code'] = substr($trackData, $offset, 5);
        $offset += 5;
    }

    // 10. Reserve (19 digits) - ASCII文字列のまま
    if ($offset + 19 <= strlen($trackData)) {
        $reserve = substr($trackData, $offset, 19);
        $data['reserve'] = $reserve;
        $data['reserve_hex'] = bin2hex($reserve);
        $offset += 19;
    }

    // 11. ETX (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['etx'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 12. CRC (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['crc'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    return $data;
}

/**
 * JIS1 2nd Trackデータをパースする
 *
 * @param string $trackDataHex 2nd Trackデータ（16進数文字列）
 * @return array パースされたデータ
 */
function parseJIS1SecondTrack(string $trackDataHex): array
{
    $trackData = pack('H*', $trackDataHex);
    $offset = 0;
    $data = [];

    // 1. STX (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['stx'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 2. Member ship Number (13 or 16 digits) - セパレータ（=）まで読み取る（ASCII文字列のまま）
    $membershipNumber = '';
    while ($offset < strlen($trackData) && $trackData[$offset] !== '=') {
        $membershipNumber .= $trackData[$offset];
        $offset += 1;
    }
    $data['membership_number'] = $membershipNumber;
    $data['membership_number_hex'] = bin2hex($membershipNumber);

    // 3. Separator (1Byte) - = - 16進数文字列として出力
    if ($offset < strlen($trackData) && $trackData[$offset] === '=') {
        $data['separator'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 4. Expire Date (4 digits) - ASCII文字列のまま
    if ($offset + 4 <= strlen($trackData)) {
        $data['expire_date'] = substr($trackData, $offset, 4);
        $offset += 4;
    }

    // 5. Service Code (3 digits) - ASCII文字列のまま
    if ($offset + 3 <= strlen($trackData)) {
        $data['service_code'] = substr($trackData, $offset, 3);
        $offset += 3;
    }

    // 6. PIN (5 digits) - ASCII文字列のまま
    if ($offset + 5 <= strlen($trackData)) {
        $data['pin'] = substr($trackData, $offset, 5);
        $offset += 5;
    }

    // 7. Reserve (8 digits) - ASCII文字列のまま
    if ($offset + 8 <= strlen($trackData)) {
        $reserve = substr($trackData, $offset, 8);
        $data['reserve'] = $reserve;
        $data['reserve_hex'] = bin2hex($reserve);
        $offset += 8;
    }

    // 8. ETX (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['etx'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    // 9. CRC (1Byte) - 16進数文字列として出力
    if ($offset < strlen($trackData)) {
        $data['crc'] = bin2hex(substr($trackData, $offset, 1));
        $offset += 1;
    }

    return $data;
}

/**
 * JIS2 Trackデータをパースする
 *
 * @param string $trackDataHex JIS2 Trackデータ（16進数文字列）
 * @return array パースされたデータ
 */
function parseJIS2Track(string $trackDataHex): array
{
    $trackData = pack('H*', $trackDataHex);
    $offset = 0;
    $data = [];

    // 1. STX (1Byte)
    if ($offset < strlen($trackData)) {
        $data['stx'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 2. ID Mark (1Byte)
    if ($offset < strlen($trackData)) {
        $data['id_mark'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 3. Biz Category Code (1Byte)
    if ($offset < strlen($trackData)) {
        $data['biz_category_code'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 4. PIN Code (4 digits)
    if ($offset + 4 <= strlen($trackData)) {
        $data['pin_code'] = substr($trackData, $offset, 4);
        $offset += 4;
    }

    // 5. Company Code (4 digits)
    if ($offset + 4 <= strlen($trackData)) {
        $data['company_code'] = substr($trackData, $offset, 4);
        $offset += 4;
    }

    // 6. Member ship Number (16 digits)
    if ($offset + 16 <= strlen($trackData)) {
        $membershipNumber = substr($trackData, $offset, 16);
        $data['membership_number'] = $membershipNumber;
        $data['membership_number_hex'] = bin2hex($membershipNumber);
        $offset += 16;
    }

    // 7. Arbitrary Data (1Byte)
    if ($offset < strlen($trackData)) {
        $data['arbitrary_data1'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 8. Arbitrary Data (1Byte)
    if ($offset < strlen($trackData)) {
        $data['arbitrary_data2'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 9. ???? (1Byte) - オン、オフ用途区分
    if ($offset < strlen($trackData)) {
        $data['on_off_flag'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 10. Reserve (10 digits)
    if ($offset + 10 <= strlen($trackData)) {
        $reserve1 = substr($trackData, $offset, 10);
        $data['reserve1'] = $reserve1;
        $data['reserve1_hex'] = bin2hex($reserve1);
        $offset += 10;
    }

    // 11. Expire Date (4 digits)
    if ($offset + 4 <= strlen($trackData)) {
        $data['expire_date'] = substr($trackData, $offset, 4);
        $offset += 4;
    }

    // 12. Reserve (25 digits)
    if ($offset + 25 <= strlen($trackData)) {
        $reserve2 = substr($trackData, $offset, 25);
        $data['reserve2'] = $reserve2;
        $data['reserve2_hex'] = bin2hex($reserve2);
        $offset += 25;
    }

    // 13. Validity Code (1Byte)
    if ($offset < strlen($trackData)) {
        $data['validity_code'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 14. ETX (1Byte)
    if ($offset < strlen($trackData)) {
        $data['etx'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    // 15. CRC (1Byte)
    if ($offset < strlen($trackData)) {
        $data['crc'] = substr($trackData, $offset, 1);
        $offset += 1;
    }

    return $data;
}

/**
 * パースされたデータを見やすく出力する
 *
 * @param array $data パースされたデータ
 */
function outputParsedData(array $data): void
{
    if ($data['type'] === 'MS') {
        outputParsedDataMS($data);
    } else {
        outputParsedDataIC($data);
    }
}

/**
 * IC用パースデータを出力する
 *
 * @param array $data パースされたデータ
 */
function outputParsedDataIC(array $data): void
{
    echo "STX: " . $data['stx'] . PHP_EOL;
    echo "LEN0: " . $data['len0'] . " (" . $data['len0_value'] . "文字)" . PHP_EOL;
    echo "KSN: " . $data['ksn'] . PHP_EOL;
    echo "TransResult: " . $data['trans_result'] . PHP_EOL;
    echo "LEN1: " . $data['len1'] . " (" . $data['len1_value'] . "文字)" . PHP_EOL;
    echo "DATA1: " . $data['data1'] . PHP_EOL;
    echo "LEN2: " . $data['len2'] . " (" . $data['len2_value'] . "文字)" . PHP_EOL;
    echo "DATA2: " . $data['data2'] . PHP_EOL;
    echo "LEN3: " . $data['len3'] . " (" . $data['len3_value'] . "文字)" . PHP_EOL;
    echo "DATA3: " . $data['data3'] . PHP_EOL;
    echo "LEN4: " . $data['len4'] . " (" . $data['len4_value'] . "文字)" . PHP_EOL;
    echo "DATA4: " . $data['data4'] . PHP_EOL;
    echo "XOR: " . $data['xor'] . PHP_EOL;
    echo "ETX: " . $data['etx'] . PHP_EOL;
    echo PHP_EOL . "=== DATA1復号化結果 ===" . PHP_EOL;
    echo "DATA1(復号化): " . $data['decrypted_data1'] . PHP_EOL;
    echo PHP_EOL . "=== DATA1 EMVパース結果 ===" . PHP_EOL;
    echo EmvParser::formatEmvData($data['emv_parsed_data1']);
    echo PHP_EOL . "=== DATA3 EMVパース結果 ===" . PHP_EOL;
    echo EmvParser::formatEmvData($data['emv_parsed_data3']);
}

/**
 * MS用パースデータを出力する
 *
 * @param array $data パースされたデータ
 */
function outputParsedDataMS(array $data): void
{
    echo "STX: " . $data['stx'] . PHP_EOL;
    echo "LEN0: " . $data['len0'] . " (" . $data['len0_value'] . "文字)" . PHP_EOL;
    echo "NUM: " . $data['num'] . " (0x05 = MS)" . PHP_EOL;
    echo "LEN1: " . $data['len1'] . " (" . $data['len1_value'] . "文字)" . PHP_EOL;
    echo "DATA1: " . $data['data1'] . PHP_EOL;
    echo "LEN2: " . $data['len2'] . " (" . $data['len2_value'] . "文字)" . PHP_EOL;
    echo "DATA2: " . $data['data2'] . PHP_EOL;
    echo "LEN3: " . $data['len3'] . " (" . $data['len3_value'] . "文字)" . PHP_EOL;
    echo "DATA3 (KSN): " . $data['data3'] . PHP_EOL;
    echo "KSN: " . $data['ksn'] . PHP_EOL;
    echo "LEN4: " . $data['len4'] . " (" . $data['len4_value'] . "文字)" . PHP_EOL;
    echo "DATA4 (RI): " . $data['data4'] . PHP_EOL;
    echo "LEN5: " . $data['len5'] . " (" . $data['len5_value'] . "文字)" . PHP_EOL;
    echo "DATA5 (MAC): " . $data['data5'] . PHP_EOL;
    echo "XOR: " . $data['xor'] . PHP_EOL;
    echo "ETX: " . $data['etx'] . PHP_EOL;
    echo PHP_EOL . "=== DATA1復号化結果 ===" . PHP_EOL;
    echo "DATA1(復号化): " . $data['decrypted_data1'] . PHP_EOL;
    echo PHP_EOL . "=== DATA1内部構造（磁気カードデータ）===" . PHP_EOL;
    $internal = $data['decrypted_data1_internal'];
    echo "STX: " . $internal['stx'] . PHP_EOL;
    echo "LEN0: " . $internal['len0'] . " (" . $internal['len0_value'] . "文字)" . PHP_EOL;
    echo "LEN1: " . $internal['len1'] . " (" . $internal['len1_value'] . "文字)" . PHP_EOL;
    echo "DATA1 (JIS1 1st Track): " . $internal['data1'] . PHP_EOL;
    if (isset($internal['data1_parsed']) && !empty($internal['data1_parsed'])) {
        echo "--- JIS1 1st Track パース結果 (JIS1 1st Track Layout) ---" . PHP_EOL;
        $track1 = $internal['data1_parsed'];
        echo "  STX: " . ($track1['stx'] ?? '') . PHP_EOL;
        echo "  Format Code: " . ($track1['format_code'] ?? '') . PHP_EOL;
        if (isset($track1['membership_number_hex']) && isset($track1['membership_number'])) {
            echo "  Member ship Number: " . $track1['membership_number_hex'] . "(" . $track1['membership_number'] . ")" . PHP_EOL;
        } else {
            echo "  Member ship Number: " . ($track1['membership_number'] ?? '') . PHP_EOL;
        }
        echo "  Separator1: " . ($track1['separator1'] ?? '') . PHP_EOL;
        if (isset($track1['holder_name_hex']) && isset($track1['holder_name'])) {
            echo "  Holder Name: " . $track1['holder_name_hex'] . "(" . $track1['holder_name'] . ")" . PHP_EOL;
        } else {
            echo "  Holder Name: " . ($track1['holder_name'] ?? '') . PHP_EOL;
        }
        echo "  Separator2: " . ($track1['separator2'] ?? '') . PHP_EOL;
        echo "  Expire Date: " . ($track1['expire_date'] ?? '') . PHP_EOL;
        echo "  Service Code: " . ($track1['service_code'] ?? '') . PHP_EOL;
        echo "  PIN Code: " . ($track1['pin_code'] ?? '') . PHP_EOL;
        if (isset($track1['reserve_hex']) && isset($track1['reserve'])) {
            echo "  Reserve: " . $track1['reserve_hex'] . "(" . $track1['reserve'] . ")" . PHP_EOL;
        } else {
            echo "  Reserve: " . ($track1['reserve'] ?? '') . PHP_EOL;
        }
        echo "  ETX: " . ($track1['etx'] ?? '') . PHP_EOL;
        echo "  CRC: " . ($track1['crc'] ?? '') . PHP_EOL;
    }
    echo "LEN2: " . $internal['len2'] . " (" . $internal['len2_value'] . "文字)" . PHP_EOL;
    echo "DATA2 (JIS1 2nd Track): " . $internal['data2'] . PHP_EOL;
    if (isset($internal['data2_parsed']) && !empty($internal['data2_parsed'])) {
        echo "--- JIS1 2nd Track パース結果 (JIS1 2nd Track Layout) ---" . PHP_EOL;
        $track2 = $internal['data2_parsed'];
        echo "  STX: " . ($track2['stx'] ?? '') . PHP_EOL;
        if (isset($track2['membership_number_hex']) && isset($track2['membership_number'])) {
            echo "  Member ship Number: " . $track2['membership_number_hex'] . "(" . $track2['membership_number'] . ")" . PHP_EOL;
        } else {
            echo "  Member ship Number: " . ($track2['membership_number'] ?? '') . PHP_EOL;
        }
        echo "  Separator: " . ($track2['separator'] ?? '') . PHP_EOL;
        echo "  Expire Date: " . ($track2['expire_date'] ?? '') . PHP_EOL;
        echo "  Service Code: " . ($track2['service_code'] ?? '') . PHP_EOL;
        echo "  PIN: " . ($track2['pin'] ?? '') . PHP_EOL;
        if (isset($track2['reserve_hex']) && isset($track2['reserve'])) {
            echo "  Reserve: " . $track2['reserve_hex'] . "(" . $track2['reserve'] . ")" . PHP_EOL;
        } else {
            echo "  Reserve: " . ($track2['reserve'] ?? '') . PHP_EOL;
        }
        echo "  ETX: " . ($track2['etx'] ?? '') . PHP_EOL;
        echo "  CRC: " . ($track2['crc'] ?? '') . PHP_EOL;
    }
    echo "LEN3: " . $internal['len3'] . " (" . $internal['len3_value'] . "文字)" . PHP_EOL;
    echo "DATA3 (JIS2 Track): " . $internal['data3'] . PHP_EOL;
    if (isset($internal['data3_parsed']) && !empty($internal['data3_parsed'])) {
        echo "--- JIS2 Track パース結果 (JIS2 Track Layout) ---" . PHP_EOL;
        $track3 = $internal['data3_parsed'];
        echo "  STX: " . ($track3['stx'] ?? '') . PHP_EOL;
        echo "  ID Mark: " . ($track3['id_mark'] ?? '') . PHP_EOL;
        echo "  Biz Category Code: " . ($track3['biz_category_code'] ?? '') . PHP_EOL;
        echo "  PIN Code: " . ($track3['pin_code'] ?? '') . PHP_EOL;
        echo "  Company Code: " . ($track3['company_code'] ?? '') . PHP_EOL;
        if (isset($track3['membership_number_hex']) && isset($track3['membership_number'])) {
            echo "  Member ship Number: " . $track3['membership_number_hex'] . "(" . $track3['membership_number'] . ")" . PHP_EOL;
        } else {
            echo "  Member ship Number: " . ($track3['membership_number'] ?? '') . PHP_EOL;
        }
        echo "  Arbitrary Data1: " . ($track3['arbitrary_data1'] ?? '') . PHP_EOL;
        echo "  Arbitrary Data2: " . ($track3['arbitrary_data2'] ?? '') . PHP_EOL;
        echo "  On/Off Flag: " . ($track3['on_off_flag'] ?? '') . PHP_EOL;
        if (isset($track3['reserve1_hex']) && isset($track3['reserve1'])) {
            echo "  Reserve1: " . $track3['reserve1_hex'] . "(" . $track3['reserve1'] . ")" . PHP_EOL;
        } else {
            echo "  Reserve1: " . ($track3['reserve1'] ?? '') . PHP_EOL;
        }
        echo "  Expire Date: " . ($track3['expire_date'] ?? '') . PHP_EOL;
        if (isset($track3['reserve2_hex']) && isset($track3['reserve2'])) {
            echo "  Reserve2: " . $track3['reserve2_hex'] . "(" . $track3['reserve2'] . ")" . PHP_EOL;
        } else {
            echo "  Reserve2: " . ($track3['reserve2'] ?? '') . PHP_EOL;
        }
        echo "  Validity Code: " . ($track3['validity_code'] ?? '') . PHP_EOL;
        echo "  ETX: " . ($track3['etx'] ?? '') . PHP_EOL;
        echo "  CRC: " . ($track3['crc'] ?? '') . PHP_EOL;
    }
    echo "XOR: " . $internal['xor'] . PHP_EOL;
    echo "ETX: " . $internal['etx'] . PHP_EOL;
    echo PHP_EOL . "=== DATA2 EMVパース結果 ===" . PHP_EOL;
    echo EmvParser::formatEmvData($data['emv_parsed_data2']);
}
