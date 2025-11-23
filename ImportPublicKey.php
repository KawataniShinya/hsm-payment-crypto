<?php

/**
 * ImportPublicKey.php - 公開鍵インポートツール
 *
 * 使用方法: php ImportPublicKey.php <PublicKey>
 *
 * 引数:
 *   PublicKey: X.509形式のBase64エンコードされた公開鍵
 *
 * 説明:
 *   X.509形式のBase64エンコードされた公開鍵をHSMにインポートします。
 *   公開鍵から実際の公開鍵データを抽出し、HSMにインポートしてMAC値を取得します。
 *   出力は16進数文字列としてMAC値を出力します。
 *
 * 例: php ImportPublicKey.php MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx1yuLfFLVheFEbWLITMyhnBplpGb3nNqXLfous+6/ZUc5Z19zwMQZqRaOU8D4MfwpBoWjF8jHVot3Pc+reFrnMyC9tc3DFQVwZoezJmTlBhAb3WDSlMfaqf6TxO7YLtQ5cbWqIgHJ4WPHfso8p1Ks7T7rtzvS/JhDhe4lnOhH/6M0xIrhp8fyr5EeJHxnIk6Jqa5f91UN3dYGcYi+I70pRm6uMti6bgSaitLqzIJzjK55zq/4PaMLljNI4/5nma77NXpl6ExC5PE9/3/f122sEOMPsFulH1LkKtKnI08b4hulL7o5kdTWxnZ8wWW/0HI/bhAKY3AQO4T/0crGHjd0QIDAQAB
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
 * 公開鍵をHSMにインポートする
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string, tmk_block: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $base64PublicKey X.509形式のBase64エンコードされた公開鍵
 * @return string 公開鍵MAC（16進数文字列）
 * @throws Exception
 */
function importPublicKey(array $property, string $base64PublicKey): string
{
    // Base64エンコードされた公開鍵から実際の公開鍵を抽出
    $publicKey = PublicKeyUtil::getPublicKeyFromX509Base64($base64PublicKey);

    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMで公開鍵インポート実行
    $pubKeyMac = $hsmClient->importPublicKey($publicKey);

    // バイナリデータを16進数文字列に変換
    return strtoupper(bin2hex($pubKeyMac));
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
            "Invalid number of arguments. Expected 1 argument: PublicKey"
        );
    }

    $publicKey = $args[0];

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
        if ($argc !== 2) {
            echo "Usage: php ImportPublicKey.php <PublicKey>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  PublicKey: X.509形式のBase64エンコードされた公開鍵\n";
            echo "\n";
            echo "Example:\n";
            echo "  php ImportPublicKey.php MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx1yuLfFLVheFEbWLITMyhnBplpGb3nNqXLfous+6/ZUc5Z19zwMQZqRaOU8D4MfwpBoWjF8jHVot3Pc+reFrnMyC9tc3DFQVwZoezJmTlBhAb3WDSlMfaqf6TxO7YLtQ5cbWqIgHJ4WPHfso8p1Ks7T7rtzvS/JhDhe4lnOhH/6M0xIrhp8fyr5EeJHxnIk6Jqa5f91UN3dYGcYi+I70pRm6uMti6bgSaitLqzIJzjK55zq/4PaMLljNI4/5nma77NXpl6ExC5PE9/3/f122sEOMPsFulH1LkKtKnI08b4hulL7o5kdTWxnZ8wWW/0HI/bhAKY3AQO4T/0crGHjd0QIDAQAB\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        $base64PublicKey = $args[0];

        echo "=== Import Public Key Tool ===\n";
        echo "Public Key (Base64): " . substr($base64PublicKey, 0, 50) . "...\n";
        echo "\n";

        // 公開鍵をインポート
        $pubKeyMacHex = importPublicKey($GLOBALS['property'], $base64PublicKey);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "Public Key MAC (HEX): " . $pubKeyMacHex . "\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
