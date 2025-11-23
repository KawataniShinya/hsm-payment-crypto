<?php

/**
 * ExportIPEKformattedTR34.php - IPEKをTR-34形式でエクスポートするツール
 *
 * 使用方法: php ExportIPEKformattedTR34.php <IPEK> <PublicKey>
 *
 * 引数:
 *   IPEK: IPEK（形式未定、DeriveIPEK.phpで生成されたIPEK）
 *   PublicKey: X.509形式のBase64エンコードされた公開鍵
 *
 * 説明:
 *   IPEKと公開鍵を使用してIPEKをTR-34形式でエクスポートします。
 *   IPEKはDeriveIPEK.phpで生成された形式未定のIPEKを想定しています。
 *   公開鍵はX.509形式のBase64エンコードされた公開鍵を指定します。
 *
 * 例: php ExportIPEKformattedTR34.php [IPEKの値] MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx1yuLfFLVheFEbWLITMyhnBplpGb3nNqXLfous+6/ZUc5Z19zwMQZqRaOU8D4MfwpBoWjF8jHVot3Pc+reFrnMyC9tc3DFQVwZoezJmTlBhAb3WDSlMfaqf6TxO7YLtQ5cbWqIgHJ4WPHfso8p1Ks7T7rtzvS/JhDhe4lnOhH/6M0xIrhp8fyr5EeJHxnIk6Jqa5f91UN3dYGcYi+I70pRm6uMti6bgSaitLqzIJzjK55zq/4PaMLljNI4/5nma77NXpl6ExC5PE9/3/f122sEOMPsFulH1LkKtKnI08b4hulL7o5kdTWxnZ8wWW/0HI/bhAKY3AQO4T/0crGHjd0QIDAQAB
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
require_once __DIR__ . '/src/PublicKeyUtil.php';

// 設定ファイルを読み込み
$property = require __DIR__ . '/src/property.php';

/**
 * IPEKをTR-34形式でエクスポートする
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string, tmk_block: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $ipek IPEK（形式未定、DeriveIPEK.phpで生成されたIPEK）
 * @param string $base64PublicKey X.509形式のBase64エンコードされた公開鍵
 * @return array{ipekTr34: string, kcv: string, signature: string} IPEK(TR-34形式、HEX文字列)、KCV(HEX文字列)、Signature(HEX文字列)
 * @throws Exception
 */
function exportIPEKFormattedTR34(array $property, string $ipek, string $base64PublicKey): array
{
    // Base64エンコードされた公開鍵から実際の公開鍵を抽出
    $publicKey = PublicKeyUtil::getPublicKeyFromX509Base64($base64PublicKey);

    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでIPEKをTR-34形式でエクスポート実行
    $ipekTr34 = $hsmClient->exportIPEKformattedTR34($ipek, $publicKey);

    return $ipekTr34;
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
    if (count($args) !== 2) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 2 arguments: IPEK, PublicKey"
        );
    }

    $ipek = $args[0];
    $publicKey = $args[1];

    // IPEKの検証（空でないことを確認）
    if (empty($ipek)) {
        throw new InvalidArgumentException("IPEK must not be empty");
    }

    // Base64文字列の基本的な検証（Base64文字のみ）
    if (!preg_match('/^[A-Za-z0-9+\/]+=*$/', $publicKey)) {
        throw new InvalidArgumentException("PublicKey must be a valid Base64 encoded string");
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
        if ($argc !== 3) {
            echo "Usage: php ExportIPEKformattedTR34.php <IPEK> <PublicKey>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  IPEK: IPEK（形式未定、DeriveIPEK.phpで生成されたIPEK）\n";
            echo "  PublicKey: X.509形式のBase64エンコードされた公開鍵\n";
            echo "\n";
            echo "Example:\n";
            echo "  php ExportIPEKformattedTR34.php [IPEKの値] MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx1yuLfFLVheFEbWLITMyhnBplpGb3nNqXLfous+6/ZUc5Z19zwMQZqRaOU8D4MfwpBoWjF8jHVot3Pc+reFrnMyC9tc3DFQVwZoezJmTlBhAb3WDSlMfaqf6TxO7YLtQ5cbWqIgHJ4WPHfso8p1Ks7T7rtzvS/JhDhe4lnOhH/6M0xIrhp8fyr5EeJHxnIk6Jqa5f91UN3dYGcYi+I70pRm6uMti6bgSaitLqzIJzjK55zq/4PaMLljNI4/5nma77NXpl6ExC5PE9/3/f122sEOMPsFulH1LkKtKnI08b4hulL7o5kdTWxnZ8wWW/0HI/bhAKY3AQO4T/0crGHjd0QIDAQAB\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        $ipek = $args[0];
        $base64PublicKey = $args[1];

        echo "=== IPEK Export Tool (TR-34 Format) ===\n";
        echo "IPEK: " . substr($ipek, 0, 50) . "...\n";
        echo "Public Key (Base64): " . substr($base64PublicKey, 0, 50) . "...\n";
        echo "\n";

        // IPEKをTR-34形式でエクスポート
        $result = exportIPEKFormattedTR34($GLOBALS['property'], $ipek, $base64PublicKey);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "ipekTr34: " . $result['ipekTr34'] . "\n";
        echo "kcv: " . $result['kcv'] . "\n";
        if (isset($result['signature'])) {
            echo "signature: " . $result['signature'] . "\n";
        }

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
