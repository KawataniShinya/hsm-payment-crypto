<?php

/**
 * DecryptECBforPIN.php - PINブロックECB復号化ツール
 *
 * 使用方法: php DecryptECBforPIN.php <PINBlock> <DecryptKey> [PAN]
 *
 * 引数:
 *   PINBlock: 暗号化されたPIN Block（16進数文字列）
 *   DecryptKey: 復号化キー（TR-31形式のキーブロック）
 *   PAN: Primary Account Number（オプション、PIN取得時に必要）
 *
 * 説明:
 *   復号化キーで暗号化されたPIN BlockをECBモードで復号化します。
 *   復号化結果は16進数文字列として出力され、0x80までのデータが抽出されます。
 *   PANが指定された場合、復号化されたPINデータからPINを取得します。
 *
 * PIN取得の流れ（XOR処理）:
 *   1. 復号化されたPINデータからPIN Block DUKを抽出
 *      - 最初の4文字（16進数）がメッセージ長
 *      - 次のメッセージ長分がPIN Block DUK（PINの桁数情報とXORマスクを含む）
 *   2. PANからアカウント番号を生成
 *      - PANのチェックデジット（最後の1桁）を削除
 *      - '0000' + 後ろから12桁で16文字のアカウント番号を生成
 *   3. XOR演算でPINを取得
 *      - アカウント番号（16進数）とPIN Block DUK（16進数）をXOR演算
 *      - 結果からPINの桁数分を抽出してPINを取得
 *
 * 例: php DecryptECBforPIN.php 38E557F9D0C2BFEE S10096D0TN00S0000B28CA98B651D07A45310FA75C45D046C0C61439D6601D3262D9FFA804C796D1FFF050B964793A84F
 * 例: php DecryptECBforPIN.php 38E557F9D0C2BFEE S10096D0TN00S0000B28CA98B651D07A45310FA75C45D046C0C61439D6601D3262D9FFA804C796D1FFF050B964793A84F 6210948000000037
 */

// エラー表示設定
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// 必要なクラスを読み込み
require_once __DIR__ . '/src/HexUtil.php';
require_once __DIR__ . '/src/PINUtil.php';
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';
require_once __DIR__ . '/src/HSMClient.php';

// 設定ファイルを読み込み
$property = require __DIR__ . '/src/property.php';

/**
 * PINブロックをECBモードで復号化する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $pinBlock PIN Block（16進数文字列）
 * @param string $decryptKey 復号化キー（TR-31形式のキーブロック）
 * @return string 復号化された16進数文字列（0x80まで）
 * @throws Exception
 */
function decryptPinBlockWithECB(array $property, string $pinBlock, string $decryptKey): string
{
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでECB復号化実行
    $decryptedHex = $hsmClient->decryptDataBlockWithECBToString($pinBlock, $decryptKey);

    // 0x80までの16進数文字列を抽出
    $resultHex = HexUtil::getHexUntil80($decryptedHex);

    return strtoupper($resultHex);
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
    if (count($args) < 2 || count($args) > 3) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 2 or 3 arguments: PINBlock, DecryptKey, [PAN]"
        );
    }

    $pinBlock = $args[0];
    $decryptKey = $args[1];
    $pan = $args[2] ?? null;

    // PIN Blockの検証（16文字の16進数）
    if (!preg_match('/^[0-9A-F]{16}$/', $pinBlock)) {
        throw new InvalidArgumentException("PINBlock must be 16 characters of hexadecimal");
    }

    // 復号化キーの検証（TR-31形式のキーブロック: Sで始まり、適切な長さ）
    if (!preg_match('/^S[0-9A-Z]{30,}$/', $decryptKey)) {
        throw new InvalidArgumentException("DecryptKey must be a valid TR-31 key block format (starts with S, alphanumeric)");
    }

    // PANの検証（オプション、数字のみ）
    if ($pan !== null && !preg_match('/^[0-9]+$/', $pan)) {
        throw new InvalidArgumentException("PAN must be numeric");
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
        if ($argc < 3 || $argc > 4) {
            echo "Usage: php DecryptECB.php <PINBlock> <DecryptKey> [PAN]\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  PINBlock:  暗号化されたPIN Block（16文字の16進数）\n";
            echo "  DecryptKey: 復号化キー（TR-31形式のキーブロック）\n";
            echo "  PAN:       Primary Account Number（オプション、PIN取得時に必要）\n";
            echo "\n";
            echo "Example:\n";
            echo "  php DecryptECB.php 38E557F9D0C2BFEE S10096D0TN00S0000B28CA98B651D07A45310FA75C45D046C0C61439D6601D3262D9FFA804C796D1FFF050B964793A84F\n";
            echo "  php DecryptECB.php 38E557F9D0C2BFEE S10096D0TN00S0000B28CA98B651D07A45310FA75C45D046C0C61439D6601D3262D9FFA804C796D1FFF050B964793A84F 6210948000000037\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        $pinBlock = $args[0];
        $decryptKey = $args[1];
        $pan = $args[2] ?? null;

        echo "=== Decrypt ECB Tool ===\n";
        echo "PIN Block: " . $pinBlock . "\n";
        echo "Decrypt Key: " . $decryptKey . "\n";
        if ($pan !== null) {
            echo "PAN: " . $pan . "\n";
        }
        echo "\n";

        // PINブロックを復号化
        $decryptedHex = decryptPinBlockWithECB($GLOBALS['property'], $pinBlock, $decryptKey);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "DUKPT復号化PINデータ: " . $decryptedHex . "\n";

        // PANが指定された場合、PINを取得
        // XOR処理の流れ:
        //   1. 復号化PINデータからPIN Block DUKを抽出（メッセージ長 + PIN Block DUK）
        //   2. PANからアカウント番号を生成（'0000' + PANの後ろ12桁、チェックデジット除外）
        //   3. アカウント番号とPIN Block DUKをXOR演算してPINを取得
        if ($pan !== null) {
            try {
                $pin = PINUtil::extractPINFromDecryptedData($decryptedHex, $pan);
                echo "PIN: " . $pin . "\n";
            } catch (Exception $e) {
                echo "Warning: PIN取得に失敗しました: " . $e->getMessage() . "\n";
            }
        }

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
