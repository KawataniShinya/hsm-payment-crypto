<?php

/**
 * TranslatePinFromEncryption.php - PIN暗号化変換ツール
 *
 * 使用方法: php TranslatePinFromEncryption.php <ZPK> <KSN> <PINBlock> <AccountNumber>
 *
 * 引数:
 *   ZPK: Zone PIN Encryption Key
 *   KSN: Key Serial Number
 *   PINBlock: 暗号化されたPIN Block（16進数文字列）
 *   AccountNumber: アカウント番号
 *
 * 説明:
 *   ZPKで暗号化されたPIN BlockをDUKPTの鍵(BDK)で暗号化されたPIN Blockに変換します。
 *
 * 例: php TranslatePinFromEncryption.php S10096P0TN00S0000D76AC3B0402D799DA896E731FF7F98A6FBAC138825AA477BC999928DDB4130F7B5D987A31CC0B3C4 5047303130020F200008 22828CA4BC2EA212 094800000003
 */

// エラー表示設定
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// 必要なクラスを読み込み
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';
require_once __DIR__ . '/src/HSMClient.php';

// 設定ファイルを読み込み
$property = require __DIR__ . '/src/property.php';

/**
 * PIN暗号化を変換する
 *
 * @param array{hsm: array{direct_hosts: array<string>, socket_connect_timeout: int, socket_connect_retry_count: int, socket_receive_timeout: int, bdk_block_3des: string}, logging: array{fullOutputFlg: bool}} $property HSM接続設定
 * @param string $zpk ZPK
 * @param string $ksn KSN
 * @param string $pinBlock PIN Block（16進数文字列）
 * @param string $accountNumber アカウント番号
 * @return string 変換後のPIN Block（16進数文字列）
 * @throws Exception
 */
function translatePinFromEncryption(array $property, string $zpk, string $ksn, string $pinBlock, string $accountNumber): string
{
    // HSMクライアントを初期化
    $hsmClient = new HSMClient($property);

    // HSMでPIN暗号化変換実行
    $destinationPinBlock = $hsmClient->translatePinFromEncryption($zpk, $ksn, $pinBlock, $accountNumber);

    return $destinationPinBlock;
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
    if (count($args) !== 4) {
        throw new InvalidArgumentException(
            "Invalid number of arguments. Expected 4 arguments: ZPK, KSN, PINBlock, AccountNumber"
        );
    }

    [$zpk, $ksn, $pinBlock, $accountNumber] = $args;

    // ZPKの検証（TR-31形式のキーブロック: Sで始まり、適切な長さ）
    if (!preg_match('/^S[0-9A-Z]{30,}$/', $zpk)) {
        throw new InvalidArgumentException("ZPK must be a valid TR-31 key block format (starts with S, alphanumeric)");
    }

    // KSNの検証（20文字の16進数）
    if (!preg_match('/^[0-9A-F]{20}$/', $ksn)) {
        throw new InvalidArgumentException("KSN must be 20 characters of hexadecimal");
    }

    // PIN Blockの検証（16文字の16進数）
    if (!preg_match('/^[0-9A-F]{16}$/', $pinBlock)) {
        throw new InvalidArgumentException("PINBlock must be 16 characters of hexadecimal");
    }

    // Account Numberの検証（12文字の数字）
    if (!preg_match('/^[0-9]{12}$/', $accountNumber)) {
        throw new InvalidArgumentException("AccountNumber must be 12 digits");
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
        if ($argc !== 5) {
            echo "Usage: php TranslatePinFromEncryption.php <ZPK> <KSN> <PINBlock> <AccountNumber>\n";
            echo "\n";
            echo "Arguments:\n";
            echo "  ZPK:          Zone PIN Encryption Key (TR-31 format)\n";
            echo "  KSN:          Key Serial Number (20 hex characters)\n";
            echo "  PINBlock:     Encrypted PIN Block (16 hex characters)\n";
            echo "  AccountNumber: Account Number (12 digits)\n";
            echo "\n";
            echo "Example:\n";
            echo "  php TranslatePinFromEncryption.php S10096P0TN00S0000D76AC3B0402D799DA896E731FF7F98A6FBAC138825AA477BC999928DDB4130F7B5D987A31CC0B3C4 5047303130020F200008 22828CA4BC2EA212 094800000003\n";
            exit(1);
        }

        // 引数を取得（最初の要素はスクリプト名なので除外）
        $args = array_slice($argv, 1);

        // 引数の検証
        validateArguments($args);

        // 引数を個別の変数に代入
        [$zpk, $ksn, $pinBlock, $accountNumber] = $args;

        echo "=== Translate PIN from Encryption Tool ===\n";
        echo "ZPK: " . $zpk . "\n";
        echo "KSN: " . $ksn . "\n";
        echo "PIN Block: " . $pinBlock . "\n";
        echo "Account Number: " . $accountNumber . "\n";
        echo "\n";

        // PIN暗号化を変換
        $destinationPinBlock = translatePinFromEncryption($GLOBALS['property'], $zpk, $ksn, $pinBlock, $accountNumber);

        // 結果を出力
        echo "=== RESULT ===\n";
        echo "Destination PIN Block: " . $destinationPinBlock . "\n";

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}

// メイン処理実行
main();
