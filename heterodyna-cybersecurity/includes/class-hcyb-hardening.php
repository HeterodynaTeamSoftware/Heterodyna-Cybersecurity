<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Hardening {

    public static function init(): void {
        add_action('send_headers', [__CLASS__, 'send_security_headers'], 10);
        add_filter('xmlrpc_enabled', [__CLASS__, 'xmlrpc_control']);
        add_filter('rest_endpoints', [__CLASS__, 'rest_endpoints_control'], 20, 1);
        add_action('init', [__CLASS__, 'block_author_enum'], 1);
        add_action('admin_init', [__CLASS__, 'disable_file_edit'], 1);
    }

    public static function profile(): array {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        return $cfg['profiles'][$active] ?? [];
    }

    public static function send_security_headers(): void {
        $p = self::profile();
        $headers = $p['headers'] ?? ['enabled'=>false];
        if (empty($headers['enabled'])) return;

        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');

        // X-Frame-Options: legacy fallback. CSP frame-ancestors lepsze, ale robimy miękko.
        header('X-Frame-Options: SAMEORIGIN');

        // HSTS (ostrożnie!)
        if (!empty($headers['hsts']) && is_ssl()) {
            header('Strict-Transport-Security: max-age=15552000; includeSubDomains'); // 180 dni
        }

        // CSP - domyślnie report-only
        $csp_mode = $headers['csp_mode'] ?? 'report'; // off|report|enforce
        if ($csp_mode !== 'off') {
            $policy = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; img-src 'self' data: blob: https:; media-src 'self' data: blob: https:; connect-src 'self' https:; frame-ancestors 'self';";
            if ($csp_mode === 'enforce') {
                header("Content-Security-Policy: $policy");
            } else {
                header("Content-Security-Policy-Report-Only: $policy");
            }
        }
    }

    public static function xmlrpc_control($enabled) {
        $p = self::profile();
        $hard = $p['hardening'] ?? [];
        $mode = $hard['xmlrpc'] ?? 'restrict'; // off|restrict|on
        if ($mode === 'off') return false;
        if ($mode === 'on') return true;
        // restrict: zostaw włączone, ale pingback wyłączymy przez filtr poniżej (proste)
        add_filter('xmlrpc_methods', function($methods) {
            unset($methods['pingback.ping']);
            unset($methods['pingback.extensions.getPingbacks']);
            return $methods;
        });
        return true;
    }

    public static function rest_endpoints_control($endpoints) {
        $p = self::profile();
        $hard = $p['hardening'] ?? [];
        $lock_users = !empty($hard['rest_users']);

        if ($lock_users && isset($endpoints['/wp/v2/users'])) {
            $endpoints['/wp/v2/users'][0]['permission_callback'] = function () { return current_user_can('list_users'); };
        }
        if ($lock_users && isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            $endpoints['/wp/v2/users/(?P<id>[\d]+)'][0]['permission_callback'] = function () { return current_user_can('list_users'); };
        }
        return $endpoints;
    }

    public static function block_author_enum(): void {
        $p = self::profile();
        $hard = $p['hardening'] ?? [];
        if (empty($hard['author_enum'])) return;

        if (!is_admin() && isset($_GET['author'])) {
            HCYB_Logger::event('low','hardening','author_enum_blocked', [
                'message' => 'Zablokowano próbę enumeracji autora',
                'meta' => ['author' => sanitize_text_field(wp_unslash($_GET['author']))],
                'status' => 404
            ]);
            status_header(404);
            exit;
        }
    }

    public static function disable_file_edit(): void {
        $p = self::profile();
        $hard = $p['hardening'] ?? [];
        if (empty($hard['file_edit'])) return;

        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
    }
}
