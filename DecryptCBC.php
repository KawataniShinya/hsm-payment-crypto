<?php

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
 * メイン処理
 */
function main() {
    global $property, $argc, $argv;

    // コマンドライン引数を取得
    if ($argc !== 3) {
        echo "Usage: php DecryptCBC.php <encryptedText> <KSN>\n";
        exit(1);
    }

    $encryptedText = $argv[1];
    $ksn = $argv[2];

    try {
        // HSMクライアントを初期化
        $hsmClient = new HSMClient($property);

        // HSMで復号化実行
        $plainText = $hsmClient->decryptDataBlockWithCBCToString($encryptedText, $ksn);

        // 結果出力
        echo PHP_EOL . "=== RESULT ===" . PHP_EOL;
        echo "decryptedText: " . $plainText . PHP_EOL;

    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
        exit(1);
    }
}

// メイン処理を実行
main();
