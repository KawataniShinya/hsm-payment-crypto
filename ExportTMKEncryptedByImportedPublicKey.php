<?php

/**
 * ExportTMKEncryptedByImportedPublicKey.php - 公開鍵暗号化TMKエクスポートツール
 *
 * 使用方法: php ExportTMKEncryptedByImportedPublicKey.php <PublicKeyMAC>
 *
 * 引数:
 *   PublicKeyMAC: 公開鍵MAC値（16進数文字列）
 *
 * 説明:
 *   インポートされた公開鍵のMAC値を使用して、TMKを公開鍵で暗号化してエクスポートします。
 *   入力は16進数文字列の公開鍵MAC値で、これをバイナリに変換して使用します。
 *   出力はBase64エンコードされた暗号化TMKです。
 *
 * 例: php ExportTMKEncryptedByImportedPublicKey.php 5331303330343032524E303053303030303082010A0282010100C75CAE2DF14B56178511B58B21333286706996919BDE736A5CB7E8BACFBAFD951CE59D7DCF031066A45A394F03E0C7F0A41A168C5F231D5A2DDCF73EADE16B9CCC82F6D7370C5415C19A1ECC99939418406F75834A531F6AA7FA4F13BB60BB50E5C6D6A8880727858F1DFB28F29D4AB3B4FBAEDCEF4BF2610E17B89673A11FFE8CD3122B869F1FCABE447891F19C893A26A6B97FDD5437775819C622F88EF4A519BAB8CB62E9B8126A2B4BAB3209CE32B9E73ABFE0F68C2E58CD238FF99E66BBECD5E997A1310B93C4F7FDFF7F5DB6B0438C3EC16E947D4B90AB4A9C8D3C6F886E94BEE8E647535B19D9F30596FF41C8FDB840298DC040EE13FF472B1878DDD10203010001F89B31353846353732413646434531383643
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
 * 公開鍵で暗号化されたTMKをエクスポートする
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string, tmk_block: string, tmk_mac: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $pubKeyMacHex 公開鍵MAC値（16進数文字列）
 * @return string 暗号化TMK（Base64エンコード）
 * @throws Exception
 */
function exportTMKEncryptedByPublicKey(array $property, string $pubKeyMacHex): string
{
    // 16進数文字列をバイナリデータに変換
    $pubKeyMac = pack('H*', $pubKeyMacHex);

    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMで公開鍵暗号化TMKエクスポート実行
    $encryptedTmkBase64 = $hsmClient->exportTMKEncryptedByPublicKey($pubKeyMac);

    return $encryptedTmkBase64;
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
            "Invalid number of arguments. Expected 1 argument: PublicKeyMAC"
        );
    }

    $pubKeyMacHex = $args[0];

    // 16進数文字列の検証
    if (!preg_match('/^[0-9A-Fa-f]+$/', $pubKeyMacHex)) {
        throw new InvalidArgumentException("PublicKeyMAC must be a valid hexadecimal string");
    }

    // 長さが偶数であることを確認（バイナリ変換のため）
    if (strlen($pubKeyMacHex) % 2 !== 0) {
        throw new InvalidArgumentException("PublicKeyMAC must have an even number of hexadecimal characters");
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
            echo "Usage: php ExportTMKEncryptedByImportedPublicKey.php <PublicKeyMAC>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  PublicKeyMAC: 公開鍵MAC値（16進数文字列）\n";
            echo "\n";
            echo "Example:\n";
            echo "  php ExportTMKEncryptedByImportedPublicKey.php 5331303330343032524E303053303030303082010A0282010100C75CAE2DF14B56178511B58B21333286706996919BDE736A5CB7E8BACFBAFD951CE59D7DCF031066A45A394F03E0C7F0A41A168C5F231D5A2DDCF73EADE16B9CCC82F6D7370C5415C19A1ECC99939418406F75834A531F6AA7FA4F13BB60BB50E5C6D6A8880727858F1DFB28F29D4AB3B4FBAEDCEF4BF2610E17B89673A11FFE8CD3122B869F1FCABE447891F19C893A26A6B97FDD5437775819C622F88EF4A519BAB8CB62E9B8126A2B4BAB3209CE32B9E73ABFE0F68C2E58CD238FF99E66BBECD5E997A1310B93C4F7FDFF7F5DB6B0438C3EC16E947D4B90AB4A9C8D3C6F886E94BEE8E647535B19D9F30596FF41C8FDB840298DC040EE13FF472B1878DDD10203010001F89B31353846353732413646434531383643\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        $pubKeyMacHex = $args[0];

        echo "=== Export TMK Encrypted by Public Key Tool ===\n";
        echo "Public Key MAC (HEX): " . substr($pubKeyMacHex, 0, 50) . "...\n";
        echo "\n";

        // 公開鍵で暗号化されたTMKをエクスポート
        $encryptedTmkBase64 = exportTMKEncryptedByPublicKey($GLOBALS['property'], $pubKeyMacHex);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "暗号化TMK: " . $encryptedTmkBase64 . "\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
