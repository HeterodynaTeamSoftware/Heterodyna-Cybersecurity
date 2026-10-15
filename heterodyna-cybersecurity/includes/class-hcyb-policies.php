<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Policies {

    public static function ensure_secret(array &$cfg): void {
        if (!empty($cfg['secret_key']) && is_string($cfg['secret_key']) && strlen($cfg['secret_key']) >= 32) {
            return;
        }
        try {
            $cfg['secret_key'] = bin2hex(random_bytes(32));
        } catch (Throwable $e) {
            $cfg['secret_key'] = wp_generate_password(64, true, true);
        }
    }

    public static function hmac_sign(string $payload_json, string $secret): string {
        return hash_hmac('sha256', $payload_json, $secret);
    }

    public static function create_snapshot(string $reason, ?int $user_id = null, string $source = 'ui'): ?int {
        $cfg = HCYB_DB::get_config('hcyb', []);
        self::ensure_secret($cfg);
        HCYB_DB::set_config('hcyb', $cfg); // zapis jeśli brakowało sekretu

        $active = (string)($cfg['profile_active'] ?? 'domyslny');
        $profile = $cfg['profiles'][$active] ?? [];

        $payload = [
            'profile_key' => $active,
            'profile' => $profile,
            'created_at' => gmdate('c'),
        ];
        $json = wp_json_encode($payload, JSON_UNESCAPED_UNICODE);
        $hash = hash('sha256', $json);

        global $wpdb;
        [$t_ver,] = HCYB_DB::tables()['policy_versions'];
        $wpdb->insert($t_ver, [
            'created_at' => gmdate('Y-m-d H:i:s'),
            'profile_key' => $active,
            'version_hash' => $hash,
            'config_json' => $json,
            'reason' => $reason,
            'user_id' => $user_id,
            'source' => $source,
        ], ['%s','%s','%s','%s','%s','%d','%s']);
        return $wpdb->insert_id ? (int)$wpdb->insert_id : null;
    }

    public static function list_snapshots(string $profile_key, int $limit = 25): array {
        global $wpdb;
        [$t_ver,] = HCYB_DB::tables()['policy_versions'];
        $limit = max(1, min(200, $limit));
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT id, created_at, version_hash, reason, user_id, source FROM $t_ver WHERE profile_key=%s ORDER BY id DESC LIMIT %d",
            $profile_key,
            $limit
        ), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    public static function get_snapshot(int $id): ?array {
        global $wpdb;
        [$t_ver,] = HCYB_DB::tables()['policy_versions'];
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $t_ver WHERE id=%d", $id), ARRAY_A);
        if (!$row) return null;
        $data = json_decode((string)$row['config_json'], true);
        if (!is_array($data)) return null;
        $row['payload'] = $data;
        return $row;
    }

    public static function rollback_to(int $snapshot_id, ?int $user_id = null): bool {
        $snap = self::get_snapshot($snapshot_id);
        if (!$snap) return false;
        $payload = $snap['payload'] ?? null;
        if (!is_array($payload)) return false;

        $cfg = HCYB_DB::get_config('hcyb', []);
        self::ensure_secret($cfg);
        $pkey = (string)($payload['profile_key'] ?? 'domyslny');
        $cfg['profiles'][$pkey] = (array)($payload['profile'] ?? []);
        $cfg['profile_active'] = $pkey;
        $ok = HCYB_DB::set_config('hcyb', $cfg);
        if ($ok) {
            self::create_snapshot('rollback:' . $snapshot_id, $user_id, 'rollback');
            HCYB_Logger::event('med', 'policy', 'rollback', [
                'message' => 'Przywrócono politykę z wersji #' . $snapshot_id,
                'meta' => ['profile' => $pkey]
            ]);
        }
        return $ok;
    }

    // Prosty diff: zwraca listę zmian w postaci [path, old, new]
    public static function diff_profile(array $a, array $b, string $prefix = ''): array {
        $changes = [];
        $keys = array_unique(array_merge(array_keys($a), array_keys($b)));
        sort($keys);
        foreach ($keys as $k) {
            $pa = $a[$k] ?? null;
            $pb = $b[$k] ?? null;
            $path = $prefix === '' ? (string)$k : ($prefix . '.' . $k);
            if (is_array($pa) && is_array($pb)) {
                $changes = array_merge($changes, self::diff_profile($pa, $pb, $path));
            } else {
                if ($pa !== $pb) {
                    $changes[] = ['path' => $path, 'old' => $pa, 'new' => $pb];
                }
            }
        }
        return $changes;
    }

    public static function export_signed(string $profile_key): array {
        $cfg = HCYB_DB::get_config('hcyb', []);
        self::ensure_secret($cfg);
        HCYB_DB::set_config('hcyb', $cfg);
        $secret = (string)$cfg['secret_key'];
        $profile = $cfg['profiles'][$profile_key] ?? [];
        $payload = [
            'kind' => 'hcyb_policy_export',
            'v' => HCYB_VERSION,
            'profile_key' => $profile_key,
            'profile' => $profile,
            'ts' => time(),
            'nonce' => wp_generate_password(16, false, false),
        ];
        $json = wp_json_encode($payload, JSON_UNESCAPED_UNICODE);
        $sig = self::hmac_sign($json, $secret);
        return ['payload' => $payload, 'sig' => $sig];
    }

    public static function import_signed(string $json, string $sig, ?int $user_id = null): bool {
        $cfg = HCYB_DB::get_config('hcyb', []);
        self::ensure_secret($cfg);
        $secret = (string)$cfg['secret_key'];
        $calc = self::hmac_sign($json, $secret);
        if (!hash_equals($calc, (string)$sig)) {
            return false;
        }
        $payload = json_decode($json, true);
        if (!is_array($payload) || ($payload['kind'] ?? '') !== 'hcyb_policy_export') return false;
        $pkey = (string)($payload['profile_key'] ?? 'domyslny');
        $cfg['profiles'][$pkey] = (array)($payload['profile'] ?? []);
        $cfg['profile_active'] = $pkey;
        $ok = HCYB_DB::set_config('hcyb', $cfg);
        if ($ok) {
            self::create_snapshot('import_signed', $user_id, 'import');
            HCYB_Logger::event('low', 'policy', 'import', [
                'message' => 'Zaimportowano politykę (podpisana).',
                'meta' => ['profile' => $pkey]
            ]);
        }
        return $ok;
    }
}
