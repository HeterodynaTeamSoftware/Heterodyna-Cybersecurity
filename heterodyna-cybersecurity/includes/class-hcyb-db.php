<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_DB {
    private static bool $inited = false;

    public static function init(): void {
        if (self::$inited) return;
        self::$inited = true;
        self::maybe_upgrade();
    }

    private static function maybe_upgrade(): void {
        // Delikatny upgrade bez psucia istniejących instalacji.
        global $wpdb;
        $tables = self::tables();
        if (!isset($tables['policy_versions'])) return;
        [$t_ver, $charset] = $tables['policy_versions'];
        $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $t_ver));
        if ($exists === $t_ver) return;
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }
        $sql = "CREATE TABLE $t_ver (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            profile_key VARCHAR(64) NOT NULL,
            version_hash VARCHAR(64) NOT NULL,
            config_json LONGTEXT NOT NULL,
            reason VARCHAR(191) NULL,
            user_id BIGINT NULL,
            source VARCHAR(32) NULL,
            PRIMARY KEY (id),
            KEY profile_key (profile_key),
            KEY created_at (created_at)
        ) $charset;";
        dbDelta($sql);
    }

    public static function tables(): array {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        $prefix = $wpdb->prefix; // tylko jako prefiks nazw - NIE używamy tabel WP
        return [
            'config' => [$prefix . 'hetsec_config', $charset],
            'events' => [$prefix . 'hetsec_events', $charset],
            'ipcache' => [$prefix . 'hetsec_ip_cache', $charset],
            'baseline' => [$prefix . 'hetsec_file_baseline', $charset],
            'kv' => [$prefix . 'hetsec_kv', $charset],
            'policy_versions' => [$prefix . 'hetsec_policy_versions', $charset],
        ];
    }

    public static function activate(): void {
        if (!function_exists('dbDelta')) {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        }
        global $wpdb;
        $tables = self::tables();

        [$t_config, $charset] = $tables['config'];
        $sql1 = "CREATE TABLE $t_config (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            config_key VARCHAR(191) NOT NULL,
            config_json LONGTEXT NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY config_key (config_key)
        ) $charset;";

        [$t_events, $charset] = $tables['events'];
        $sql2 = "CREATE TABLE $t_events (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            level VARCHAR(20) NOT NULL,
            category VARCHAR(50) NOT NULL,
            action VARCHAR(50) NOT NULL,
            ip VARCHAR(64) NULL,
            country VARCHAR(8) NULL,
            asn VARCHAR(32) NULL,
            user_id BIGINT NULL,
            method VARCHAR(10) NULL,
            path TEXT NULL,
            status INT NULL,
            rule_id VARCHAR(64) NULL,
            message TEXT NULL,
            meta LONGTEXT NULL,
            PRIMARY KEY (id),
            KEY created_at (created_at),
            KEY category (category),
            KEY ip (ip(32))
        ) $charset;";

        [$t_ipcache, $charset] = $tables['ipcache'];
        $sql3 = "CREATE TABLE $t_ipcache (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip VARCHAR(64) NOT NULL,
            provider VARCHAR(50) NOT NULL,
            country VARCHAR(8) NULL,
            asn VARCHAR(32) NULL,
            org VARCHAR(191) NULL,
            risk_score INT NULL,
            raw_json LONGTEXT NULL,
            cached_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_provider (ip, provider),
            KEY expires_at (expires_at)
        ) $charset;";

        [$t_baseline, $charset] = $tables['baseline'];
        $sql4 = "CREATE TABLE $t_baseline (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path TEXT NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT NULL,
            file_mtime BIGINT NULL,
            scope VARCHAR(20) NOT NULL,
            baseline_id VARCHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY baseline_id (baseline_id),
            KEY scope (scope(10))
        ) $charset;";

        [$t_kv, $charset] = $tables['kv'];
        $sql5 = "CREATE TABLE $t_kv (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            kv_key VARCHAR(191) NOT NULL,
            kv_value LONGTEXT NULL,
            updated_at DATETIME NOT NULL,
            expires_at DATETIME NULL,
            PRIMARY KEY (id),
            UNIQUE KEY kv_key (kv_key),
            KEY expires_at (expires_at)
        ) $charset;";

        dbDelta($sql1);
        dbDelta($sql2);
        dbDelta($sql3);
        dbDelta($sql4);
        dbDelta($sql5);

        [$t_ver, $charset] = $tables['policy_versions'];
        $sql6 = "CREATE TABLE $t_ver (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            profile_key VARCHAR(64) NOT NULL,
            version_hash VARCHAR(64) NOT NULL,
            config_json LONGTEXT NOT NULL,
            reason VARCHAR(191) NULL,
            user_id BIGINT NULL,
            source VARCHAR(32) NULL,
            PRIMARY KEY (id),
            KEY profile_key (profile_key),
            KEY created_at (created_at)
        ) $charset;";
        dbDelta($sql6);

        self::seed_defaults();
    }

    public static function deactivate(): void {
        // Nie usuwamy tabel, by nie tracić logów. Usuwanie można dodać jako opcję w ustawieniach.
    }

    private static function seed_defaults(): void {
        $defaults = [
            'secret_key' => '',
            'profile_active' => 'domyslny',
            'profiles' => [
                'domyslny' => [
                    'name' => 'Domyślny (bezpieczny)',
                    'waf' => [
                        'enabled' => true,
                        'mode' => 'monitor',
                        'block_level' => 'low',
                        'fingerprint' => true,
                        'ip_allow' => [],
                        'ip_deny' => [],
                        'rate_limits' => [
                            'wp_login' => ['enabled'=>true, 'max'=>25, 'window_sec'=>300, 'block_sec'=>900, 'only_methods'=>['POST']],
                            'xmlrpc' => ['enabled'=>true, 'max'=>10, 'window_sec'=>300, 'block_sec'=>1800, 'only_methods'=>['POST']],
                            'rest' => ['enabled'=>false, 'max'=>120, 'window_sec'=>60, 'block_sec'=>600, 'only_methods'=>[]],
                            'admin_ajax' => ['enabled'=>false, 'max'=>240, 'window_sec'=>60, 'block_sec'=>600, 'only_methods'=>[]],
                        ],
                    ],
                    'headers' => ['enabled' => true, 'hsts' => false, 'csp_mode' => 'report'],
                    'hardening' => ['xmlrpc' => 'restrict', 'rest_users' => true, 'author_enum' => true, 'file_edit' => true],
                    'login' => ['enabled' => true, 'max_attempts' => 8, 'window_sec' => 900, 'lock_sec' => 1800],
                    'scanner' => ['enabled' => true],
                    'allow' => [
                        'uploads_allow' => true,
                        'paths_allow' => [
                            '/wp-content/uploads/',
                            '/wp-admin/upload.php',
                            '/wp-admin/async-upload.php',
                            '/wp-admin/admin-ajax.php',
                        ],
                        'hosts' => []
                    ],
                    'ip_reputation' => ['enabled' => false, 'provider' => 'ipapi', 'ttl_days' => 14],
                    'alerts' => ['enabled'=>false,'emails'=>'','min_level'=>'high','cooldown_sec'=>600],
                    'digest' => ['enabled'=>false,'emails'=>'','day_of_week'=>1,'hour'=>9,'period_days'=>7],
                    'privacy' => ['ip_mode' => 'full'],
                    'adaptive' => ['enabled'=>false,'window_min'=>5,'threshold'=>60,'duration_min'=>60],
                    'retention_days' => 30
                ],
                'twardy' => [
                    'name' => 'Twardy (blokuj)',
                    'waf' => [
                        'enabled' => true,
                        'mode' => 'block',
                        'block_level' => 'med',
                        'fingerprint' => true,
                        'ip_allow' => [],
                        'ip_deny' => [],
                        'rate_limits' => [
                            'wp_login' => ['enabled'=>true, 'max'=>12, 'window_sec'=>300, 'block_sec'=>1800, 'only_methods'=>['POST']],
                            'xmlrpc' => ['enabled'=>true, 'max'=>3, 'window_sec'=>300, 'block_sec'=>3600, 'only_methods'=>['POST']],
                            'rest' => ['enabled'=>true, 'max'=>80, 'window_sec'=>60, 'block_sec'=>900, 'only_methods'=>[]],
                            'admin_ajax' => ['enabled'=>true, 'max'=>160, 'window_sec'=>60, 'block_sec'=>900, 'only_methods'=>[]],
                        ],
                    ],
                    'headers' => ['enabled' => true, 'hsts' => true, 'csp_mode' => 'report'],
                    'hardening' => ['xmlrpc' => 'off', 'rest_users' => true, 'author_enum' => true, 'file_edit' => true],
                    'login' => ['enabled' => true, 'max_attempts' => 5, 'window_sec' => 900, 'lock_sec' => 3600],
                    'scanner' => ['enabled' => true],
                    'allow' => [
                        'uploads_allow' => true,
                        'paths_allow' => [
                            '/wp-content/uploads/',
                            '/wp-admin/upload.php',
                            '/wp-admin/async-upload.php',
                            '/wp-admin/admin-ajax.php',
                        ],
                        'hosts' => []
                    ],
                    'ip_reputation' => ['enabled' => false, 'provider' => 'ipapi', 'ttl_days' => 14],
                    'alerts' => ['enabled'=>false,'emails'=>'','min_level'=>'high','cooldown_sec'=>600],
                    'digest' => ['enabled'=>false,'emails'=>'','day_of_week'=>1,'hour'=>9,'period_days'=>7],
                    'privacy' => ['ip_mode' => 'full'],
                    'adaptive' => ['enabled'=>true,'window_min'=>5,'threshold'=>40,'duration_min'=>120],
                    'retention_days' => 45
                ]
            ],
        ];
        // sekret do podpisywania eksportów/importów polityk
        if (empty($defaults['secret_key'])) {
            try { $defaults['secret_key'] = bin2hex(random_bytes(32)); }
            catch (Throwable $e) { $defaults['secret_key'] = wp_generate_password(64, true, true); }
        }
        self::set_config('hcyb', $defaults);
    }

    public static function get_config(string $key, $default = null) {
        global $wpdb;
        [$t_config,] = self::tables()['config'];
        $row = $wpdb->get_row($wpdb->prepare("SELECT config_json FROM $t_config WHERE config_key=%s", $key));
        if (!$row) return $default;
        $json = (string)$row->config_json;
        $data = json_decode($json, true);
        return is_array($data) ? $data : $default;
    }

    public static function set_config(string $key, $data): bool {
        global $wpdb;
        [$t_config,] = self::tables()['config'];
        $json = wp_json_encode($data, JSON_UNESCAPED_UNICODE);
        $now = gmdate('Y-m-d H:i:s');
        $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM $t_config WHERE config_key=%s", $key));
        if ($exists) {
            return (bool)$wpdb->update($t_config, ['config_json' => $json, 'updated_at' => $now], ['config_key' => $key], ['%s','%s'], ['%s']);
        }
        return (bool)$wpdb->insert($t_config, ['config_key' => $key, 'config_json' => $json, 'updated_at' => $now], ['%s','%s','%s']);
    }

    

    // IP cache (reputacja/geo) - w 100% we własnej tabeli
    public static function ip_cache_get(string $ip, string $provider = 'local_heuristic'): ?array {
        global $wpdb;
        [$t_ipcache,] = self::tables()['ipcache'];
        $now = gmdate('Y-m-d H:i:s');
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $t_ipcache WHERE ip=%s AND provider=%s AND (expires_at IS NULL OR expires_at > %s) LIMIT 1", $ip, $provider, $now), ARRAY_A);
        return $row ?: null;
    }

    public static function ip_cache_set(string $ip, string $provider, ?string $country, ?string $asn, ?string $org, ?int $risk_score, ?string $raw_json, string $expires_at): bool {
        global $wpdb;
        [$t_ipcache,] = self::tables()['ipcache'];
        $now = gmdate('Y-m-d H:i:s');
        $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM $t_ipcache WHERE ip=%s AND provider=%s", $ip, $provider));
        $data = [
            'ip' => $ip,
            'provider' => $provider,
            'country' => $country,
            'asn' => $asn,
            'org' => $org,
            'risk_score' => $risk_score,
            'raw_json' => $raw_json,
            'cached_at' => $now,
            'expires_at' => $expires_at,
        ];
        $formats = ['%s','%s','%s','%s','%s','%d','%s','%s','%s'];
        if ($exists) {
            return (bool)$wpdb->update($t_ipcache, $data, ['id' => (int)$exists], $formats, ['%d']);
        }
        return (bool)$wpdb->insert($t_ipcache, $data, $formats);
    }

public static function kv_get(string $key, $default = null) {
        global $wpdb;
        [$t_kv,] = self::tables()['kv'];
        $now = gmdate('Y-m-d H:i:s');
        $row = $wpdb->get_row($wpdb->prepare("SELECT kv_value, expires_at FROM $t_kv WHERE kv_key=%s", $key));
        if (!$row) return $default;
        if (!empty($row->expires_at) && $row->expires_at < $now) return $default;
        $val = $row->kv_value;
        $decoded = json_decode((string)$val, true);
        return $decoded !== null ? $decoded : $val;
    }

    public static function kv_set(string $key, $value, ?int $ttl_sec = null): bool {
        global $wpdb;
        [$t_kv,] = self::tables()['kv'];
        $now = gmdate('Y-m-d H:i:s');
        $expires = null;
        if ($ttl_sec !== null) {
            $expires = gmdate('Y-m-d H:i:s', time() + $ttl_sec);
        }
        $store = is_string($value) ? $value : wp_json_encode($value, JSON_UNESCAPED_UNICODE);
        $exists = $wpdb->get_var($wpdb->prepare("SELECT id FROM $t_kv WHERE kv_key=%s", $key));
        if ($exists) {
            return (bool)$wpdb->update($t_kv, ['kv_value' => $store, 'updated_at' => $now, 'expires_at' => $expires], ['kv_key' => $key], ['%s','%s','%s'], ['%s']);
        }
        return (bool)$wpdb->insert($t_kv, ['kv_key' => $key, 'kv_value' => $store, 'updated_at' => $now, 'expires_at' => $expires], ['%s','%s','%s','%s']);
    }
}
