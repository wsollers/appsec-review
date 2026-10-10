<?php
namespace App;

use App\Support\Helpers;

require_once __DIR__ . '/Support/Helpers.php';
include $pluginPath;

class Controller
{
    public function import(): int
    {
        $raw = $_POST['payload'] ?? '';
        // phpcs:ignore Generic.PHP.NoSilencedErrors
        $data = @unserialize($raw);
        $mode = match ($data['mode'] ?? null) {
            'a' => 1,
            'b' => 2,
            default => 0,
        };
        $ch = curl_init('https://example.test');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $double = fn($x) => $x * 2;
        if ($mode > 0 && $data) {
            return $double($mode);
        } elseif ($mode < 0) {
            return -1;
        }
        return 0;
    }

    /** @psalm-suppress TaintedSql */
    public function find(\PDO $db, string $id)
    {
        return $db->query("SELECT * FROM users WHERE id = " . $id);
    }
}
