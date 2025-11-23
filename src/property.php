<?php

/**
 * HSM接続設定と鍵情報のプロパティファイル
 */

return [
    // HSM接続設定
    'hsm' => [
        'direct_hosts' => ['tcp://192.168.8.202:1500'], // HSMサーバーの接続先
        'socket_connect_timeout' => 5,
        'socket_connect_retry_count' => 3,
        'socket_receive_timeout' => 3,

        // 鍵情報（.envから取得した実際の値）
        'bdk_block_3des' => 'S10096B0TN00S0000FD2196304A9F78B4844B0719E4DFBACD97ABA9E94A05EFB3BFD3F754CC626643675DE7D3A50FBE45',
        'tmk_block' => 'S1009651TB00S000037B591D7EE516769C656FBF603B9EF7A4121DB4BC3524E267F1C4C7F31DF0B44FF17EABD9EE2D68F',
        'tmk_mac' => '2020A20000000000', // TMK MAC値
    ],

    // ログ設定
    'logging' => [
        'fullOutputFlg' => true, // 開発用のログ全出力モード
    ],

    // キーコンポーネント設定
    'key_components' => [
        // ZPK (Zone PIN Key) のキーコンポーネント
        'zpk' => [
            'kc1' => 'S10096P0TNc1S0000816322732222F2BAA5F86DD0FEAED1CC16B9E691DE42682F89BFD0C630B853DEE46C8D24A7883E7F',
            'kc2' => 'S10096P0TNc1S00003E325E7C8C60B6DF5CB6D37A95F64902795837374D9A1309B6ED6DBFC504A8ED1C625C3A6312A0AC',
        ],
        // ZEK (Zone Encryption Key) のキーコンポーネント
        'zek' => [
            'kc1' => 'S10096D0TNc1S0000D13944E7E144EF048383ED2010D0C623A4493CBF4437A2D1AF7791D33EB1D97C6278B62164A04E6C',
            'kc2' => 'S10096D0TNc1S00001A756410932B702AA8D4A17DB6B8F1CB987912CF2B4ED922602AE1FE9E68FAB82BE3BFE8F50E19ED',
        ],
    ],
];
