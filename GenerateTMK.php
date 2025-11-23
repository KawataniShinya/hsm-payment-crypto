<?php

/**
 * GenerateTMK.php - TMK生成ツール
 *
 * 使用方法: php GenerateTMK.php
 *
 * 引数: なし
 *
 * 例: php GenerateTMK.php
 */

// エラー表示設定
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// 必要なクラスを読み込み
require_once __DIR__ . '/src/HSMClient.php';
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';

// 設定ファイルを読み込み
$property = require __DIR__ . '/src/property.php';

/**
 * TMK生成を実行する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @return array{tmk: string, checkValue: string} TMK With Check Value
 * @throws Exception
 */
function generateTMK(array $property): array {
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでTMK生成実行
    $tmkWithCheck = $hsmClient->exportTMK();

    return $tmkWithCheck;
}

/**
 * メイン処理
 */
function main(): void {
    global $argc, $argv;

    try {
        // コマンドライン引数を取得
        if ($argc !== 1) {
            echo "Usage: php GenerateTMK.php\n";
            echo "\n";
            echo "Arguments: None\n";
            echo "\n";
            echo "Example:\n";
            echo "  php GenerateTMK.php\n";
            exit(1);
        }

        echo "=== TMK Generation Tool ===" . PHP_EOL;
        echo PHP_EOL;

        // TMKを生成
        $tmkWithCheck = generateTMK($GLOBALS['property']);

        // 結果を出力
        echo "=== RESULT ===" . PHP_EOL;
        echo "TMK: " . $tmkWithCheck['tmk'] . PHP_EOL;
        echo "checkValueRightPaddedTo16Digits: " . str_pad($tmkWithCheck['checkValue'], 16, '0', STR_PAD_RIGHT) . PHP_EOL;

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
}

// メイン処理実行
main();