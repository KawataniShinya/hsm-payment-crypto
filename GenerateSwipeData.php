<?php

/**
 * GenerateSwipeData.php - スワイプデータ生成ツール
 *
 * 使用方法: php GenerateSwipeData.php
 *
 * 設定は profile.php と property.php で行う
 */

// エラー表示設定
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// 必要なクラスを読み込み
require_once __DIR__ . '/src/HexUtil.php';
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';
require_once __DIR__ . '/src/HSMClient.php';

// 設定ファイルを読み込み
$property = require __DIR__ . '/src/property.php';
$profile = require __DIR__ . '/profile.php';

/**
 * 復号化文字列とIVに分解する
 *
 * @param string $encryptedTextWithIv 復号化文字列+IV（末尾16文字）
 * @return array{encryptedText: string, iv: string}
 */
function splitEncryptedTextAndIv(string $encryptedTextWithIv): array {
    $totalLength = strlen($encryptedTextWithIv);
    $ivLength = 16; // IVは末尾16文字

    $encryptedText = substr($encryptedTextWithIv, 0, $totalLength - $ivLength);
    $iv = substr($encryptedTextWithIv, -$ivLength);

    return [
        'encryptedText' => $encryptedText,
        'iv' => $iv
    ];
}

/**
 * IC用カード情報の暗号化処理
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $cardInfoEmv 暗号化EMVデータ
 * @param string $ksn KSN
 * @return array{encryptedText: string, iv: string}
 * @throws Exception
 */
function encryptCardInfoEmv(array $property, string $cardInfoEmv, string $ksn): array {
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // 16進数文字列をバイナリデータに変換
    $plainText = pack('H*', $cardInfoEmv);

    // HSMで暗号化実行（KSNを指定）
    $encryptedHex = $hsmClient->encryptDataBlock($plainText, $ksn);

    // HSMから返される16進数文字列を10進数に変換してから文字に変換
    $encryptedTextWithIv = HexUtil::convertHexToStringUntil80($encryptedHex);

    // 復号化文字列とIVに分解
    return splitEncryptedTextAndIv($encryptedTextWithIv);
}

/**
 * 16進数文字列の長さを算出する
 *
 * @param string $hexString 16進数文字列
 * @return string 16進数4桁左0埋めの長さ（バイト数）
 */
function calculateHexLength(string $hexString): string {
    $byteLength = strlen($hexString) / 2; // 16進数文字列のバイト数
    return strtoupper(str_pad(dechex($byteLength), 4, '0', STR_PAD_LEFT));
}

/**
 * MAC対象文字列のMAC値を算出する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $macTargetData MAC算出対象文字列（16進数文字列）
 * @param string $ksn KSN
 * @return string MAC値
 * @throws Exception
 */
function generateMacValue(array $property, string $macTargetData, string $ksn): string {
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // 16進数文字列をバイナリデータに変換
    $macTargetBinary = pack('H*', $macTargetData);

    // HSMでMAC生成実行
    $macString = $hsmClient->generateMAC($macTargetBinary, $ksn);

    return $macString;
}

/**
 * 結果出力処理
 *
 * @param array{ksn: string, encryptedText: string} $result 暗号化結果
 */
function outputResult(array $result): void {
    echo 'KSN: ' . $result['ksn'] . PHP_EOL;
    echo 'encryptedText: ' . $result['encryptedText'] . PHP_EOL;
}

/**
 * MS用の処理（未実装）
 */
function mainMS(): void {
    echo "MS processing is not implemented yet." . PHP_EOL;
    exit(1);
}

/**
 * IC用の処理
 */
function mainIC(): void {
    global $property, $profile;

    $stx = $profile['ic']['stx'];
    $len0 = '';
    $ksn = $profile['ic']['ksn'];
    $transResult = $profile['ic']['transResult'];
    $len1 = '';
    $data1 = '';
    $len2 = '';
    $data2 = $profile['ic']['data2'];
    $len3 = '';
    $data3 = $profile['ic']['data3'];
    $len4 = '';
    $data4 = '';
    $xor = '';
    $etx = $profile['ic']['etx'];

    try {
        // ステップ1: カード情報EMVの暗号化
        $encryptResult = encryptCardInfoEmv(
            $property,
            $profile['ic']['card_info_emv'],
            $ksn
        );
        $data1 = $encryptResult['encryptedText'];
        $iv = $encryptResult['iv'];

        // ステップ2: DATA1(カード情報EMV暗号文)の長さを算出
        $len1 = calculateHexLength($data1);

        // ステップ3: DATA2(オンラインPIN暗号文)の長さを算出
        $len2 = calculateHexLength($data2);

        // ステップ4: DATA3(カード情報平文)の長さを算出
        $len3 = calculateHexLength($data3);

        // ステップ5: DATA4(MAC値)を算出
        $data4 = generateMacValue($property, $ksn . $transResult . $len1 . $data1 . $len2 . $data2 . $len3 . $data3, $ksn);

        // ステップ6: DATA4(MAC値)の長さを算出
        $len4 = calculateHexLength($data4);

        // ステップ7: 全体の長さを算出
        $len0 = calculateHexLength($ksn . $transResult . $len1 . $data1 . $len2 . $data2 . $len3 . $data3. $len4 . $data4);

        // ステップ8: XOR値を算出
        $xorTargetData = $ksn . $transResult . $len1 . $data1 . $len2 . $data2 . $len3 . $data3 . $len4 . $data4;
        $xor = HexUtil::calculateXorChecksum($xorTargetData);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }

    echo PHP_EOL . "=== RESULT ===" . PHP_EOL;
    echo 'swipe_data: '
        . strtolower(
            $stx . $len0 . $ksn . $transResult . $len1 . $data1 . $len2 . $data2 . $len3 . $data3 . $len4 . $data4 . $xor . $etx
        )
        . PHP_EOL;
}

/**
 * メイン処理
 */
function main(): void {
    global $argc, $argv;

    // コマンドライン引数を取得
    if ($argc !== 2) {
        echo "Usage: php GenerateSwipeData.php <mode>\n";
        echo "  mode: 0 for MS, 1 for IC\n";
        exit(1);
    }

    $mode = (int)$argv[1];

    // モードに応じて処理を分岐
    switch ($mode) {
        case 0:
            mainMS();
            break;
        case 1:
            mainIC();
            break;
        default:
            echo "Invalid mode. Use 0 for MS or 1 for IC.\n";
            exit(1);
    }
}

// メイン処理実行
main();
