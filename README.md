# HSM (payShield10K) Command Tools

HSM（Hardware Security Module）payShield10Kのコマンドを実行するスタンドアロンPHPツールです。

## 概要

payShield10K HSMの各種コマンドを実行できます。主に以下の機能を提供します：

- **スワイプデータ生成**: クレジットカードの完全なスワイプデータを生成
- **スワイプデータパース**: 生成されたスワイプデータをパース

## ファイル構成

```
HSMPaymentCryptoGit/
├── GenerateSwipeData.php    # スワイプデータ生成ツール
├── ParseSwipeData.php        # スワイプデータパーサー
├── profile.php               # ユーザー設定ファイル
├── README.md                 # このファイル
└── src/                      # プログラムクラス群
    ├── HexUtil.php           # 16進数文字列操作ユーティリティ
    ├── HSMClient.php         # HSM接続クライアント
    ├── HSMCommandGenerator.php # HSMコマンド生成
    ├── HSMResponseParser.php   # HSMレスポンス解析
    ├── HSMSocketManager.php    # HSMソケット管理
    ├── EmvParser.php          # EMVデータパーサー
    └── property.php           # HSM接続設定（内部設定）
```

## 必要な環境と前提

- PHP 7.4以上
- HSMへのネットワーク接続
- 柔軟に生成結果を得るには入力設定のための前提知識が必要
  - PAYGATE STATION SDK
  - EMV tag ([EMV® Specifications & Associated Bulletins](https://www.emvco.com/specifications/))

## ツール詳細

### 1. GenerateSwipeData.php

クレジットカードの完全なスワイプデータを生成するメインツールです。\
入力設定は`profile.php`に記述します。

#### 使用方法

##### IC処理（実装済み）

```bash
php GenerateSwipeData.php 1
```

##### MS処理（未実装）

```bash
php GenerateSwipeData.php 0
```

#### 出力例

```
swipe_data: 0201a45047303130021000000402015085018838c7ce613c6cd8ef2c622e02a456c323dc5d225176d41d68aeec90caee9b2cfdbd240b0f940a773c77333169f807b375667f33dfb3a369e2e29fdf268a6f29e85a4a86b8fc2f78de749a96fe1472102e0d6cb36029a594a86af6b42b2b237491400d86960c8b0f39e1fa2a69b5fd74e2ee8a741895c07a3f737a77312abc9b5c6aaa21edce45ae7cd8e9155fc1730305ada352324e53d5143e6fbf0891bedaac0904e162b2f93e7ee61d5e33974c2a1deb852e778bf142961c545ccf6499432814807ed45920966e6e0ec028c2e3e3a6e408755089bd59c9f93f2bd5b870a617eb1fc3d2ebf5975371237cf5fddb2eb4b3620330253b9cd7764b8cb7b63c1ec90300fe1bac76bb63191f238b6b5f23e12a04a4339e8efb570935cc0771209ec52b65275c88c79a7704c9c2999cf3eae4e76094fc60eb7fd1dc18dfde57c2e9bfcdf79951d23b69eec2846468010000003d5a08358746ffffff06925f300202015f200d545241494e494e4720434152445f280201569505088008e0005f24032708319f3303c0b8e89f34031e030000042cf561929703
```

#### 生成されるスワイプデータの構成

| フィールド | 説明 | 例 |
|-----------|------|-----|
| STX | 開始文字（0x02） | 02 |
| LEN0 | 全体の長さ（16進数4桁） | 01a4 |
| KSN | キーシリアル番号 | 50473031300210000004 |
| TransResult | 取引結果 | 02 |
| LEN1 | DATA1の長さ | 0201 |
| DATA1 | 暗号化されたEMVデータ | 5085018838c7ce... |
| LEN2 | DATA2の長さ | 0000 |
| LEN3 | DATA3の長さ | 003d |
| DATA3 | カード情報平文 | 5a08358746... |
| LEN4 | DATA4の長さ | 0004 |
| DATA4 | MAC値 | 2cf56192 |
| XOR | XORチェックサム | 97 |
| ETX | 終了文字（0x03） | 03 |

### 2. ParseSwipeData.php

GenerateSwipeData.phpの逆処理として、スワイプデータをパースするツールです。IC処理とMS（磁気カード）処理に対応しています。NUMフィールド（0x05）の有無で自動的にIC/MSを判別します。

#### 使用方法

```bash
php ParseSwipeData.php <swipeData>
```

#### パラメータ

- `swipeData`: パース対象のスワイプデータ（16進数文字列）

#### IC処理の実行例

```bash
php ParseSwipeData.php 0201845047303530000220053902013886e99969ba86497106843dda0bfc5fea927e2cfb6c469e76aa5fd80d55b97f3a0a867368908de7bf6e88503518153d9b8cfabddc48d9ecb6ef6b12f602b2d3277a4be3d561681d2595c6657f6f2d1acdb75043c25998cfd2f9d5acfbecba2ed38a7a0e1835999711489b55c2301a1fc3348a40c67d4dd32859ac91dac027c573aebfac841bca2bc26a2f4796b581f18f032e8bc58854ce5a64a3c1979596a26c87fa59c60cffb043c998ec7225ef0c256a9d06a5d8e48656942e78016eb1c5e8bd002bb5b4a7798fa4a25685309ab2f18363be52e02364a2329ced208ecf644466f64893b9918f2b2e24a47761db0c70404e197f3fdf6446ff9cd081f72c11d1b16ea4a1d66290727e1238264bf89bd46025e1fc21e247d15970efe667f14e4969fa1e4d3991ccb17f9bd64ca82dfd8476679348b7800433000000355a0a621094ffffffffff152f950504c00488005f200855494343465431355f24031010315f280201569f3303e0f8c89f340342030000041d69466acf03
```

#### IC処理の期待値

```
=== RESULT ===
STX: 02
LEN0: 0184 (388文字)
KSN: 50473035300002200539
TransResult: 02
LEN1: 0138 (312文字)
DATA1: 86e99969ba86497106843dda0bfc5fea927e2cfb6c469e76aa5fd80d55b97f3a0a867368908de7bf6e88503518153d9b8cfabddc48d9ecb6ef6b12f602b2d3277a4be3d561681d2595c6657f6f2d1acdb75043c25998cfd2f9d5acfbecba2ed38a7a0e1835999711489b55c2301a1fc3348a40c67d4dd32859ac91dac027c573aebfac841bca2bc26a2f4796b581f18f032e8bc58854ce5a64a3c1979596a26c87fa59c60cffb043c998ec7225ef0c256a9d06a5d8e48656942e78016eb1c5e8bd002bb5b4a7798fa4a25685309ab2f18363be52e02364a2329ced208ecf644466f64893b9918f2b2e24a47761db0c70404e197f3fdf6446ff9cd081f72c11d1b16ea4a1d66290727e1238264bf89bd46025e1fc21e247d15970efe667f14e4969fa1e4d3991ccb17f9bd64ca82dfd8476679348b7800433
LEN2: 0000 (0文字)
DATA2: 
LEN3: 0035 (53文字)
DATA3: 5a0a621094ffffffffff152f950504c00488005f200855494343465431355f24031010315f280201569f3303e0f8c89f3403420300
LEN4: 0004 (4文字)
DATA4: 1d69466a
XOR: cf
ETX: 03

=== DATA1復号化結果 ===
DATA1(復号化): 4f08a000000333010102500b554943432043524544495457136210948000000000152d10102200000000000f5a0a6210948000000000152f82027d008408a0000003330101028a0200008e0e000000000000000042031e031f00950504c00488009a032510069b02e8009c01005f200855494343465431355f24031010315f25030510315f280201565f2a0203925f300202205f3401009f02060000000015009f03060000000000009f0702ff009f080200309f090200209f0d05d8609ca8009f0e0500100000009f0f05d8689cf8009f100807000103a00000019f1a0203929f1e0836323030303539349f1f0e32303135303632353133323334359f21031601079f26080ec20be99e0bc0449f2701809f3303e0f8c89f34034203009f3501229f360200029f37042cd0d4569f41040000133700000000

=== DATA1 EMVパース結果 ===
Tag: 4f (Application Identifier (AID)) - Length: 8 - Value: a000000333010102
Tag: 50 (Application Label) - Length: 11 - Value: 5549434320435245444954
Tag: 57 (Track 2 Equivalent Data) - Length: 19 - Value: 6210948000000000152d10102200000000000f
Tag: 5a (Application Primary Account Number (PAN)) - Length: 10 - Value: 6210948000000000152f
Tag: 82 (Application Interchange Profile) - Length: 2 - Value: 7d00
Tag: 84 (Dedicated File (DF) Name) - Length: 8 - Value: a000000333010102
Tag: 8a (Authorization Response Code) - Length: 2 - Value: 0000
Tag: 8e (Cardholder Verification Method (CVM) List) - Length: 14 - Value: 000000000000000042031e031f00
Tag: 95 (Terminal Verification Results) - Length: 5 - Value: 04c0048800
Tag: 9a (Transaction Date) - Length: 3 - Value: 251006
Tag: 9b (Transaction Status Information) - Length: 2 - Value: e800
Tag: 9c (Transaction Type) - Length: 1 - Value: 00
Tag: 5f20 (Cardholder Name) - Length: 8 - Value: 5549434346543135
Tag: 5f24 (Application Expiration Date) - Length: 3 - Value: 101031
Tag: 5f25 (Application Effective Date) - Length: 3 - Value: 051031
Tag: 5f28 (Issuer Country Code) - Length: 2 - Value: 0156
Tag: 5f2a (Transaction Currency Code) - Length: 2 - Value: 0392
Tag: 5f30 (Service Code) - Length: 2 - Value: 0220
Tag: 5f34 (Application Primary Account Number Sequence Number) - Length: 1 - Value: 00
Tag: 9f02 (Amount, Authorised (Numeric)) - Length: 6 - Value: 000000001500
Tag: 9f03 (Amount, Other (Numeric)) - Length: 6 - Value: 000000000000
Tag: 9f07 (Application Usage Control) - Length: 2 - Value: ff00
Tag: 9f08 (Application Version Number) - Length: 2 - Value: 0030
Tag: 9f09 (Application Version Number) - Length: 2 - Value: 0020
Tag: 9f0d (Issuer Action Code - Denial) - Length: 5 - Value: d8609ca800
Tag: 9f0e (Issuer Action Code - Online) - Length: 5 - Value: 0010000000
Tag: 9f0f (Issuer Application Data) - Length: 5 - Value: d8689cf800
Tag: 9f10 (Issuer Application Data) - Length: 8 - Value: 07000103a0000001
Tag: 9f1a (Terminal Country Code) - Length: 2 - Value: 0392
Tag: 9f1e (Interface Device (IFD) Serial Number) - Length: 8 - Value: 3632303030353934
Tag: 9f1f (Track 1 Discretionary Data) - Length: 14 - Value: 3230313530363235313332333435
Tag: 9f21 (Transaction Time) - Length: 3 - Value: 160107
Tag: 9f26 (Application Cryptogram) - Length: 8 - Value: 0ec20be99e0bc044
Tag: 9f27 (Cryptogram Information Data) - Length: 1 - Value: 80
Tag: 9f33 (Terminal Capabilities) - Length: 3 - Value: e0f8c8
Tag: 9f34 (Cardholder Verification Method (CVM) Results) - Length: 3 - Value: 420300
Tag: 9f35 (Terminal Type) - Length: 1 - Value: 22
Tag: 9f36 (Application Transaction Counter (ATC)) - Length: 2 - Value: 0002
Tag: 9f37 (Unpredictable Number) - Length: 4 - Value: 2cd0d456
Tag: 9f41 (Transaction Sequence Counter) - Length: 4 - Value: 00001337

=== DATA3 EMVパース結果 ===
Tag: 5a (Application Primary Account Number (PAN)) - Length: 10 - Value: 621094ffffffffff152f
Tag: 95 (Terminal Verification Results (TVR)) - Length: 5 - Value: 04c0048800
Tag: 5f20 (Cardholder Name) - Length: 8 - Value: 5549434346543135
Tag: 5f24 (Application Expiration Date (YYMMDD)) - Length: 3 - Value: 101031
Tag: 5f28 (Issuer Country Code) - Length: 2 - Value: 0156
Tag: 9f33 (Terminal Capabilities) - Length: 3 - Value: e0f8c8
Tag: 9f34 (Cardholder Verification Method (CVM) Results) - Length: 3 - Value: 420300
```

#### MS（磁気カード）JIS1処理の実行例

```bash
php ParseSwipeData.php 0200B405007042684055AF987076D8D9CF51141E53E5B5F29C317F4E01FCFAA6A1EA4CD323EB781B5CA0E68B1CF64E1371C52BDC4DAC5ADA187098FF7BBA960EDE6F203249715E0ECC027B81D3D899AFB5068658BFCF98E2F7CA4101FC1AC90FDE3DBCEF992655B407669BACA19EACA97A8659C7756C00255A08498607FFFFFF31555F24032505315F300202015F20085A45524F2F504F535F28009500000A5047303130020F200003000000043332343000047DD2E02ABE03
```

#### MS（磁気カード）JIS1処理の期待値

```
=== RESULT ===
STX: 02
LEN0: 00b4 (180文字)
NUM: 05 (0x05 = MS)
LEN1: 0070 (112文字)
DATA1: 42684055af987076d8d9cf51141e53e5b5f29c317f4e01fcfaa6a1ea4cd323eb781b5ca0e68b1cf64e1371c52bdc4dac5ada187098ff7bba960ede6f203249715e0ecc027b81d3d899afb5068658bfcf98e2f7ca4101fc1ac90fde3dbcef992655b407669baca19eaca97a8659c7756c
LEN2: 0025 (37文字)
DATA2: 5a08498607ffffff31555f24032505315f300202015f20085a45524f2f504f535f28009500
LEN3: 000a (10文字)
DATA3 (KSN): 5047303130020f200003
KSN: 5047303130020f200003
LEN4: 00000004 (4文字)
DATA4 (RI): 33323430
LEN5: 0004 (4文字)
DATA5 (MAC): 7dd2e02a
XOR: be
ETX: 03

=== DATA1復号化結果 ===
DATA1(復号化): 0200683d2542343938363037393830383035333135355e5a45524f2f504f535e323530353230313030303030202020202020202030303635353030303030303f04283b343938363037393830383035333135353d32353035323031303030303036353530303030303f34001403800000

=== DATA1内部構造（磁気カードデータ）===
STX: 02
LEN0: 0068 (104文字)
LEN1: 3d (61文字)
DATA1 (JIS1 1st Track): 2542343938363037393830383035333135355e5a45524f2f504f535e323530353230313030303030202020202020202030303635353030303030303f04
--- JIS1 1st Track パース結果 (JIS1 1st Track Layout) ---
  STX: 25
  Format Code: 42
  Member ship Number: 34393836303739383038303533313535(4986079808053155)
  Separator1: 5e
  Holder Name: 5a45524f2f504f53(ZERO/POS)
  Separator2: 5e
  Expire Date: 2505
  Service Code: 201
  PIN Code: 00000
  Reserve: 20202020202020203030363535303030303030(        00655000000)
  ETX: 3f
  CRC: 04
LEN2: 28 (40文字)
DATA2 (JIS1 2nd Track): 3b343938363037393830383035333135353d32353035323031303030303036353530303030303f34
--- JIS1 2nd Track パース結果 (JIS1 2nd Track Layout) ---
  STX: 3b
  Member ship Number: 34393836303739383038303533313535(4986079808053155)
  Separator: 3d
  Expire Date: 2505
  Service Code: 201
  PIN: 00000
  Reserve: 3635353030303030(65500000)
  ETX: 3f
  CRC: 34
LEN3: 00 (0文字)
DATA3 (JIS2 Track): 
XOR: 14
ETX: 03

=== DATA2 EMVパース結果 ===
Tag: 5a (Application Primary Account Number (PAN)) - Length: 8 - Value: 498607ffffff3155
Tag: 5f24 (Application Expiration Date (YYMMDD)) - Length: 3 - Value: 250531
Tag: 5f30 (Service Code) - Length: 2 - Value: 0201
Tag: 5f20 (Cardholder Name) - Length: 8 - Value: 5a45524f2f504f53
Tag: 5f28 (Issuer Country Code) - Length: 0 - Value: 
Tag: 95 (Terminal Verification Results (TVR)) - Length: 0 - Value: 
```

> **注意**: MS処理では、DATA2がEMV形式の平文データとして格納されています。DATA1は暗号化された磁気カードデータ（内部に1st Track、2nd Track、JISII Trackを含む）で、復号化後に内部構造がパースされます。

#### MS（磁気カード）JIS2処理の実行例

```bash
php ParseSwipeData.php 0200920500585083EC2EA2AB371B48AA5CFFB8620AC414AB8102DF2B700DA10460F0A45BEECF3145483105CB8CACDD5841EB83CAA19525998210391D32F07ED1F87367C74C32C255FFE09B042604B591E20C596DEF566CE80F7F662C0CE3001B5A08498607FFFFFF31555F24032505315F30005F20005F28009500000A5047303130020F200004000000043332343000044E4B17FDA903
```

#### MS（磁気カード）JIS2処理の期待値

```
=== RESULT ===
STX: 02
LEN0: 0092 (146文字)
NUM: 05 (0x05 = MS)
LEN1: 0058 (88文字)
DATA1: 5083ec2ea2ab371b48aa5cffb8620ac414ab8102df2b700da10460f0a45beecf3145483105cb8cacdd5841eb83caa19525998210391d32f07ed1f87367c74c32c255ffe09b042604b591e20c596def566ce80f7f662c0ce3
LEN2: 001b (27文字)
DATA2: 5a08498607ffffff31555f24032505315f30005f20005f28009500
LEN3: 000a (10文字)
DATA3 (KSN): 5047303130020f200004
KSN: 5047303130020f200004
LEN4: 00000004 (4文字)
DATA4 (RI): 33323430
LEN5: 0004 (4文字)
DATA5 (MAC): 4e4b17fd
XOR: a9
ETX: 03

=== DATA1復号化結果 ===
DATA1(復号化): 02004b0000487f6139303030303936363434393836303739383038303533313535333031303030303030323430363235303530303030303030303030303030303030303030303036353938307f1236038000000000000000

=== DATA1内部構造（磁気カードデータ）===
STX: 02
LEN0: 004b (75文字)
LEN1: 00 (0文字)
DATA1 (JIS1 1st Track): 
LEN2: 00 (0文字)
DATA2 (JIS1 2nd Track): 
LEN3: 48 (72文字)
DATA3 (JIS2 Track): 7f6139303030303936363434393836303739383038303533313535333031303030303030323430363235303530303030303030303030303030303030303030303036353938307f12
--- JIS2 Track パース結果 (JIS2 Track Layout) ---
  STX: 
  ID Mark: a
  Biz Category Code: 9
  PIN Code: 0000
  Company Code: 9664
  Member ship Number: 34393836303739383038303533313535(4986079808053155)
  Arbitrary Data1: 3
  Arbitrary Data2: 0
  On/Off Flag: 1
  Reserve1: 30303030303032343036(0000002406)
  Expire Date: 2505
  Reserve2: 30303030303030303030303030303030303030303036353938(0000000000000000000006598)
  Validity Code: 0
  ETX: 
  CRC: 
XOR: 36
ETX: 03

=== DATA2 EMVパース結果 ===
Tag: 5a (Application Primary Account Number (PAN)) - Length: 8 - Value: 498607ffffff3155
Tag: 5f24 (Application Expiration Date (YYMMDD)) - Length: 3 - Value: 250531
Tag: 5f30 (Service Code) - Length: 0 - Value: 
Tag: 5f20 (Cardholder Name) - Length: 0 - Value: 
Tag: 5f28 (Issuer Country Code) - Length: 0 - Value: 
Tag: 95 (Terminal Verification Results (TVR)) - Length: 0 - Value:  
```

> **注意**: JIS2処理では、DATA1内部構造にJISII Trackデータのみが含まれ、1st Trackと2nd Trackは空です。JISII TrackはJIS2 Track Layoutに従ってパースされます。
