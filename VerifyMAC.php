<?php

/**
 * VerifyMAC.php - MAC検証ツール
 *
 * 使用方法: php VerifyMAC.php <macTargetData> <KSN> <MAC>
 *
 * 引数:
 *   macTargetData: MAC検証対象データ（16進数文字列）
 *   KSN: KSN値（20文字の16進数）
 *   MAC: 検証するMAC値（16進数文字列）
 *
 * 例: php VerifyMAC.php 5047303530000220053902013886e99969ba86497106843dda0bfc5fea927e2cfb6c469e76aa5fd80d55b97f3a0a867368908de7bf6e88503518153d9b8cfabddc48d9ecb6ef6b12f602b2d3277a4be3d561681d2595c6657f6f2d1acdb75043c25998cfd2f9d5acfbecba2ed38a7a0e1835999711489b55c2301a1fc3348a40c67d4dd32859ac91dac027c573aebfac841bca2bc26a2f4796b581f18f032e8bc58854ce5a64a3c1979596a26c87fa59c60cffb043c998ec7225ef0c256a9d06a5d8e48656942e78016eb1c5e8bd002bb5b4a7798fa4a25685309ab2f18363be52e02364a2329ced208ecf644466f64893b9918f2b2e24a47761db0c70404e197f3fdf6446ff9cd081f72c11d1b16ea4a1d66290727e1238264bf89bd46025e1fc21e247d15970efe667f14e4969fa1e4d3991ccb17f9bd64ca82dfd8476679348b7800433000000355a0a621094ffffffffff152f950504c00488005f200855494343465431355f24031010315f280201569f3303e0f8c89f3403420300 50473035300002200539 50473035300002200539
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

/**
 * MAC検証を実行する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $macTargetData MAC検証対象データ（16進数文字列）
 * @param string $ksn KSN
 * @param string $macString 検証するMAC値（16進数文字列）
 * @return bool 検証結果
 * @throws Exception
 */
function verifyMacValue(array $property, string $macTargetData, string $ksn, string $macString): bool {
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // 16進数文字列をバイナリデータに変換
    $macTargetBinary = pack('H*', $macTargetData);

    // HSMでMAC検証実行
    $isVerified = $hsmClient->verifyMAC($macTargetBinary, $ksn, $macString);

    return $isVerified;
}

/**
 * 引数の検証
 *
 * @param array $args コマンドライン引数
 * @return void
 * @throws InvalidArgumentException
 */
function validateArguments(array $args): void {
    if (count($args) !== 3) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 3 arguments: macTargetData, KSN, MAC"
        );
    }

    // 各引数の基本的な検証
    $macTargetData = $args[0];
    $ksn = $args[1];
    $macString = $args[2];

    // MAC対象データの検証（16進数文字列）
    if (!preg_match('/^[0-9A-Fa-f]*$/', $macTargetData)) {
        throw new InvalidArgumentException("macTargetData must be hexadecimal string");
    }

    // KSNの検証（20文字の16進数）
    if (!preg_match('/^[0-9A-Fa-f]{20}$/', $ksn)) {
        throw new InvalidArgumentException("KSN must be 20 characters of hexadecimal");
    }

    // MAC値の検証（16進数文字列）
    if (!preg_match('/^[0-9A-Fa-f]*$/', $macString)) {
        throw new InvalidArgumentException("MAC must be hexadecimal string");
    }
}

/**
 * メイン処理
 */
function main(): void {
    global $argc, $argv;

    try {
        // コマンドライン引数を取得
        if ($argc !== 4) {
            echo "Usage: php VerifyMAC.php <macTargetData> <KSN> <MAC>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  macTargetData: MAC検証対象データ（16進数文字列）※実際の検証はバイナリ変換されたデータが対象\n";
            echo "  KSN:          KSN値（20文字の16進数）\n";
            echo "  MAC:          検証するMAC値（16進数文字列）\n";
            echo "\n";
            echo "Example:\n";
            echo "  php VerifyMAC.php 5047303530000220053902013886e99969ba86497106843dda0bfc5fea927e2cfb6c469e76aa5fd80d55b97f3a0a867368908de7bf6e88503518153d9b8cfabddc48d9ecb6ef6b12f602b2d3277a4be3d561681d2595c6657f6f2d1acdb75043c25998cfd2f9d5acfbecba2ed38a7a0e1835999711489b55c2301a1fc3348a40c67d4dd32859ac91dac027c573aebfac841bca2bc26a2f4796b581f18f032e8bc58854ce5a64a3c1979596a26c87fa59c60cffb043c998ec7225ef0c256a9d06a5d8e48656942e78016eb1c5e8bd002bb5b4a7798fa4a25685309ab2f18363be52e02364a2329ced208ecf644466f64893b9918f2b2e24a47761db0c70404e197f3fdf6446ff9cd081f72c11d1b16ea4a1d66290727e1238264bf89bd46025e1fc21e247d15970efe667f14e4969fa1e4d3991ccb17f9bd64ca82dfd8476679348b7800433000000355a0a621094ffffffffff152f950504c00488005f200855494343465431355f24031010315f280201569f3303e0f8c89f3403420300 50473035300002200539 1D69466A\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        [$macTargetData, $ksn, $macString] = $args;

        echo "=== MAC Verification Tool ===" . PHP_EOL;
        echo "MAC Target Data: " . $macTargetData . PHP_EOL;
        echo "KSN: " . $ksn . PHP_EOL;
        echo "MAC: " . $macString . PHP_EOL;
        echo PHP_EOL;

        // MAC値を検証
        $isVerified = verifyMacValue($GLOBALS['property'], $macTargetData, $ksn, $macString);

        // 結果を出力
        echo "=== RESULT ===" . PHP_EOL;
        $returnMessage = $isVerified ? 'Verified' : 'Not Verified';
        echo "isVerified: " . $returnMessage . PHP_EOL;

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
}

// メイン処理実行
main();
