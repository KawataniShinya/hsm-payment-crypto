<?php

/**
 * HSMソケット管理クラス
 */

class HSMSocketManager
{
    /**
     * @var array<int, string>|null HSMホストのリスト
     */
    private array|null $hsmHosts;

    /**
     * @var int 接続タイムアウト(sec)
     */
    private int $connectTimeoutSeconds;

    /**
     * @var int リトライ回数
     */
    private int $maxRetryCount;

    /**
     * @var resource|null ソケットリソース
     */
    private $socket = null;

    public function __construct(array $config)
    {
        $this->hsmHosts = $config['hsm']['direct_hosts'];
        $this->connectTimeoutSeconds = $config['hsm']['socket_connect_timeout'];
        $this->maxRetryCount = $config['hsm']['socket_connect_retry_count'];

        if (empty($this->hsmHosts)) {
            throw new Exception('HSM hosts configuration is empty');
        }
    }

    /**
     * ランダムに選択されたHSMに接続し、ソケットを設定
     *
     * @throws Exception
     */
    public function connect(): void
    {
        $hosts = $this->hsmHosts;
        shuffle($hosts);

        // HSMホストをランダム順でリトライ回数ずつ接続試行
        foreach ($hosts as $hsmHost) {
            for ($attempt = 1; $attempt <= $this->maxRetryCount; $attempt++) {
                $hsmSocket = @stream_socket_client($hsmHost, $errorCode, $errorMessage, $this->connectTimeoutSeconds);

                if ($hsmSocket) {
                    $this->socket = $hsmSocket; // ソケットをプロパティに格納
                    echo "Connected to HSM: $hsmHost\n";
                    return;
                }

                if ($attempt === $this->maxRetryCount) {
                    echo "Failed to connect to HSM: $hsmHost (attempt $attempt)\n";
                } else {
                    echo "Retrying connection to HSM: $hsmHost (attempt $attempt)\n";
                }
            }
        }

        throw new Exception('Failed to connect to any HSM host');
    }

    /**
     * ソケットの切断とリソースの開放
     *
     * @return void
     */
    public function disconnect(): void
    {
        if ($this->isConnected()) {
            // 書き込み側をシャットダウン
            stream_socket_shutdown($this->socket, STREAM_SHUT_RDWR);

            // ソケットを閉じる
            fclose($this->socket);

            // プロパティをnullに設定してリソースを解放
            $this->socket = null;
            echo "Disconnected from HSM\n";
        }
    }

    /**
     * 接続されているかを確認する
     *
     * @return bool
     */
    public function isConnected(): bool
    {
        return $this->socket !== null;
    }

    /**
     * ソケットリソースを取得
     *
     * @return resource|null ソケットリソース
     */
    public function getSocket(): mixed
    {
        return $this->socket;
    }
}
