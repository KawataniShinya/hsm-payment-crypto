<?php

/**
 * FormKeyFromEncryptedComponents.php - キーコンポーネントからキーを生成するツール
 *
 * 使用方法: php FormKeyFromEncryptedComponents.php <keyType>
 *
 * 引数:
 *   keyType: 生成するキーの種類 (zpk または zek)
 *     - zpk: ZPK (Zone PIN Key) を生成
 *     - zek: ZEK (Zone Encryption Key) を生成
 *
 * 例: php FormKeyFromEncryptedComponents.php zpk
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
 * キーコンポーネントからキーを生成する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}, key_components: array{zpk: array{kc1: string, kc2: string}, zek: array{kc1: string, kc2: string}}} $property HSM接続設定
 * @param string $keyType キーの種類 (zpk または zek)
 * @return string 生成されたキーの文字列（16進数からデコード済み）
 * @throws Exception
 */
function formKeyFromComponents(array $property, string $keyType): string
{
    // キータイプの検証
    if (!isset($property['key_components'][$keyType])) {
        throw new InvalidArgumentException("Invalid key type: $keyType. Must be 'zpk' or 'zek'.");
    }

    // キーコンポーネントを取得
    $kc1 = $property['key_components'][$keyType]['kc1'];
    $kc2 = $property['key_components'][$keyType]['kc2'];

    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでキー生成実行（16進数文字列として取得）
    $resultHex = $hsmClient->formKeyFromEncryptedComponents($kc1, $kc2);

    // 16進数文字列を文字列にデコード
    $resultString = HexUtil::convertHexToString($resultHex);

    return $resultString;
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
            "Invalid number of arguments. Expected 1 argument: keyType (zpk or zek)"
        );
    }

    $keyType = $args[0];

    // キータイプの検証
    if (!in_array($keyType, ['zpk', 'zek'], true)) {
        throw new InvalidArgumentException("keyType must be 'zpk' or 'zek'");
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
            echo "Usage: php FormKeyFromEncryptedComponents.php <keyType>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  keyType:  生成するキーの種類 (zpk または zek)\n";
            echo "            - zpk: ZPK (Zone PIN Key) を生成\n";
            echo "            - zek: ZEK (Zone Encryption Key) を生成\n";
            echo "\n";
            echo "Example:\n";
            echo "  php FormKeyFromEncryptedComponents.php zpk\n";
            echo "  php FormKeyFromEncryptedComponents.php zek\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        [$keyType] = $args;

        echo "=== Form Key from Encrypted Components Tool ===\n";
        echo "Key Type: " . strtoupper($keyType) . "\n";
        echo "\n";

        // キーを生成
        $keyValue = formKeyFromComponents($GLOBALS['property'], $keyType);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "Generated Key: " . $keyValue . "\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
