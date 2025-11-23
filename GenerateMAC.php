<?php

/**
 * GenerateMAC.php - MAC生成ツール
 *
 * 使用方法: php GenerateMAC.php <targetText> <ksn>
 *
 * 引数:
 *   targetText: ターゲットテキスト（全ての項目の文字列を結合した文字列）
 *   ksn: KSN値
 *
 * 例: php GenerateMAC.php 0000000000000000000100001001234567890ABCDEF000812345678000887654321 00000000000000000001
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
 * 引数の検証
 *
 * @param array $args コマンドライン引数
 * @return void
 * @throws InvalidArgumentException
 */
function validateArguments(array $args): void {
    if (count($args) !== 2) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 2 arguments: targetText, ksn"
        );
    }

    // 各引数の基本的な検証
    $targetText = $args[0];
    $ksn = $args[1];

    // ターゲットテキストの検証（16進数文字列）
    if (!preg_match('/^[0-9A-Fa-f]*$/', $targetText)) {
        throw new InvalidArgumentException("targetText must be hexadecimal string");
    }

    // KSNの検証（20文字の16進数）
    if (!preg_match('/^[0-9A-Fa-f]{20}$/', $ksn)) {
        throw new InvalidArgumentException("KSN must be 20 characters of hexadecimal");
    }
}

/**
 * メイン処理
 */
function main(): void {
    global $argc, $argv;

    try {
        // コマンドライン引数を取得
        if ($argc !== 3) {
            echo "Usage: php GenerateMAC.php <targetText> <ksn>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  targetText: ターゲットテキスト（全ての項目の文字列を結合した文字列）※実際の検証はバイナリ変換されたデータが対象\n";
            echo "  ksn:        KSN値（20文字の16進数）\n";
            echo "\n";
            echo "Example:\n";
            echo "  php GenerateMAC.php 0000000000000000000100001001234567890ABCDEF000812345678000887654321 00000000000000000001\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        [$targetText, $ksn] = $args;

        echo "=== MAC Generation Tool ===" . PHP_EOL;
        echo "Target Text: " . $targetText . PHP_EOL;
        echo "KSN: " . $ksn . PHP_EOL;
        echo PHP_EOL;

        // MAC値を生成
        $macValue = generateMacValue($GLOBALS['property'], $targetText, $ksn);

        // 結果を出力
        echo "=== RESULT ===" . PHP_EOL;
        echo "MAC Value: " . $macValue . PHP_EOL;

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
}

// メイン処理実行
main();
