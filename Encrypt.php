<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/src/HSMClient.php';
require_once __DIR__ . '/src/HSMCommandGenerator.php';
require_once __DIR__ . '/src/HSMResponseParser.php';
require_once __DIR__ . '/src/HSMSocketManager.php';
require_once __DIR__ . '/src/HexUtil.php';
require_once __DIR__ . '/src/property.php';

// コマンドライン引数を取得
if ($argc !== 3) {
    echo "Usage: php Encrypt.php <plainText> <KSN>\n";
    echo "  plainText: 暗号化対象の16進数文字列\n";
    echo "  KSN: キーシリアル番号\n";
    exit(1);
}

$plainText = $argv[1];
$ksn = $argv[2];

try {
    // 設定を読み込み
    $config = require __DIR__ . '/src/property.php';

    // HSMクライアントを初期化
    $hsmClient = new HSMClient($config);

    // 16進数文字列をバイナリデータに変換
    $plainTextBinary = pack('H*', $plainText);

    // 暗号化実行
    $encryptedText = $hsmClient->encryptDataBlock($plainTextBinary, $ksn);

    // HexUtilを使用して結果を処理
    $processedText = HexUtil::convertHexToStringUntil80($encryptedText);

    // 結果出力
    echo PHP_EOL . "=== RESULT ===" . PHP_EOL;
    echo "KSN: " . $ksn . PHP_EOL;
    echo "encryptedText: " . $processedText . PHP_EOL;

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    exit(1);
}
