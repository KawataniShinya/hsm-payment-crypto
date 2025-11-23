<?php

/**
 * DeriveIPEK.php - IPEK生成ツール
 *
 * 使用方法: php DeriveIPEK.php <IKSN>
 *
 * 引数:
 *   IKSN: Initial Key Serial Number（15文字の16進数）
 *
 * 説明:
 *   BDKとTMKを使用してIPEK（Initial PIN Encryption Key）を生成します。
 *   IKSNを引数として受け取り、HSMでIPEKを生成します。
 *   生成されたIPEKの形式は定まっておらず、後続処理でTR-34形式で出力する想定です。
 *
 * 例: php DeriveIPEK.php 504730313000002
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
 * IPEKを生成する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string, tmk_block: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $iksn IKSN（Initial Key Serial Number）
 * @return array{ipek: string, kcv: string} IPEKとKCV
 * @throws Exception
 */
function deriveIPEK(array $property, string $iksn): array
{
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでIPEK生成実行
    $ipek = $hsmClient->deriveIPEK($iksn);

    return $ipek;
}

/**
 * 引数の検証
 *
 * @param array $args コマンドライン引数
 * @return void
 * @throws InvalidArgumentException
 */
function validateArguments(array $args): void
{
    if (count($args) !== 1) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 1 argument: IKSN"
        );
    }

    $iksn = $args[0];

    // IKSNの検証（15文字の16進数）
    if (!preg_match('/^[0-9A-F]{15}$/', $iksn)) {
        throw new InvalidArgumentException("IKSN must be 15 characters of hexadecimal");
    }
}

/**
 * メイン処理
 */
function main(): void
{
    global $argc, $argv;

    try {
        // コマンドライン引数を取得
        if ($argc !== 2) {
            echo "Usage: php DeriveIPEK.php <IKSN>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  IKSN: Initial Key Serial Number（15文字の16進数）\n";
            echo "\n";
            echo "Example:\n";
            echo "  php DeriveIPEK.php 504730313000002\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        $iksn = $args[0];

        echo "=== IPEK Derivation Tool ===\n";
        echo "IKSN: " . $iksn . "\n";
        echo "\n";

        // IPEKを生成
        $ipekWithKcv = deriveIPEK($GLOBALS['property'], $iksn);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "ipek: " . $ipekWithKcv['ipek'] . "\n";
        echo "kcv: " . $ipekWithKcv['kcv'] . "\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
