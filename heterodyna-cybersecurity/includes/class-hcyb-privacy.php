<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Privacy {
    public static function init(): void {}

    public static function ip_mode(): string {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $mode = (string)($p['privacy']['ip_mode'] ?? 'full');
        return in_array($mode, ['full','masked','hash','off'], true) ? $mode : 'full';
    }

    public static function normalize_ip(?string $ip): ?string {
        if (!$ip) return null;
        $mode = self::ip_mode();
        if ($mode === 'off') return null;
        if ($mode === 'full') return $ip;
        if ($mode === 'masked') return self::mask_ip($ip);
        if ($mode === 'hash') return self::hash_ip($ip);
        return $ip;
    }

    public static function mask_ip(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            if (count($parts) === 4) {
                $parts[3] = '0';
                return implode('.', $parts);
            }
            return $ip;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $bin = @inet_pton($ip);
            if ($bin === false) return $ip;
            $bytes = unpack('C*', $bin);
            for ($i = 7; $i <= 16; $i++) { $bytes[$i] = 0; }
            $packed = pack('C*', ...array_values($bytes));
            $out = @inet_ntop($packed);
            return $out ?: $ip;
        }
        return $ip;
    }

    public static function hash_ip(string $ip): string {
        $salt = (string)HCYB_DB::kv_get('hcyb_ip_salt', '');
        if (strlen($salt) < 16) {
            try { $salt = bin2hex(random_bytes(16)); }
            catch (Throwable $e) { $salt = wp_generate_password(32, true, true); }
            HCYB_DB::kv_set('hcyb_ip_salt', $salt, 3650 * 86400);
        }
        return 'h:' . substr(hash('sha256', $salt . '|' . $ip), 0, 32);
    }
}
