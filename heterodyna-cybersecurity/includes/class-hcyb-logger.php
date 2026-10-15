<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Logger {
    public static function init(): void {
        // rotacja/retencja przy okazji ruchu (lekko)
        add_action('shutdown', [__CLASS__, 'retention_cleanup'], 1);
    }

    public static function event(string $level, string $category, string $action, array $ctx = []): void {
        global $wpdb;
        $tables = HCYB_DB::tables();
        [$t_events,] = $tables['events'];

        $ip_raw = $ctx['ip'] ?? self::client_ip();
        $ip = class_exists('HCYB_Privacy') ? HCYB_Privacy::normalize_ip($ip_raw) : $ip_raw;
        $method = $ctx['method'] ?? ($_SERVER['REQUEST_METHOD'] ?? null);
        $path = $ctx['path'] ?? (isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : null);
        $status = $ctx['status'] ?? null;
        $rule_id = $ctx['rule_id'] ?? null;
        $message = $ctx['message'] ?? null;
        $meta = $ctx['meta'] ?? null;
        $user_id = $ctx['user_id'] ?? (is_user_logged_in() ? get_current_user_id() : null);

        $country = $ctx['country'] ?? null;
        $asn = $ctx['asn'] ?? null;

        $wpdb->insert($t_events, [
            'created_at' => gmdate('Y-m-d H:i:s'),
            'level' => substr($level,0,20),
            'category' => substr($category,0,50),
            'action' => substr($action,0,50),
            'ip' => $ip ? substr($ip,0,64) : null,
            'country' => $country ? substr($country,0,8) : null,
            'asn' => $asn ? substr($asn,0,32) : null,
            'user_id' => $user_id,
            'method' => $method ? substr($method,0,10) : null,
            'path' => $path,
            'status' => is_numeric($status) ? (int)$status : null,
            'rule_id' => $rule_id ? substr($rule_id,0,64) : null,
            'message' => $message,
            'meta' => $meta ? wp_json_encode($meta, JSON_UNESCAPED_UNICODE) : null,
        ], ['%s','%s','%s','%s','%s','%s','%s','%d','%s','%s','%d','%s','%s','%s']);

        // Alerty e-mail (opcjonalne, z cooldown)
        if (class_exists('HCYB_Alerts')) {
            try {
                $ctx2 = $ctx;
                $ctx2['ip'] = $ip;
                HCYB_Alerts::maybe_notify($level, $category, $action, $ctx2);
            }
            catch (Throwable $e) { /* bezpiecznie ignorujemy */ }
        }
    }

    public static function cleanup_events_older_than_days(int $days): int {
        if ($days < 7) $days = 7;
        global $wpdb;
        [$t_events,] = HCYB_DB::tables()['events'];
        $cut = gmdate('Y-m-d H:i:s', time() - ($days * 86400));
        $res = $wpdb->query($wpdb->prepare("DELETE FROM $t_events WHERE created_at < %s", $cut));
        return is_numeric($res) ? (int)$res : 0;
    }

    public static function client_ip(): ?string {
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];
        foreach ($candidates as $k) {
            if (empty($_SERVER[$k])) continue;
            $raw = (string)$_SERVER[$k];
            if ($k === 'HTTP_X_FORWARDED_FOR') {
                $raw = explode(',', $raw)[0] ?? $raw;
            }
            $ip = trim($raw);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
        return null;
    }

    public static function retention_cleanup(): void {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $profiles = $cfg['profiles'] ?? [];
        $ret = (int)($profiles[$active]['retention_days'] ?? 30);
        if ($ret < 7) $ret = 7;

        // co 12h
        $last = (int)HCYB_DB::kv_get('hcyb_ret_last', 0);
        if (time() - $last < 12 * 3600) return;
        HCYB_DB::kv_set('hcyb_ret_last', time(), 48 * 3600);

        global $wpdb;
        [$t_events,] = HCYB_DB::tables()['events'];
        $cut = gmdate('Y-m-d H:i:s', time() - ($ret * 86400));
        $wpdb->query($wpdb->prepare("DELETE FROM $t_events WHERE created_at < %s", $cut));
    }
}
