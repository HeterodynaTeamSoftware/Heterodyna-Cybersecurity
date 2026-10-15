<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Login_Protect {

    public static function init(): void {
        add_filter('authenticate', [__CLASS__, 'rate_limit_auth'], 5, 3);
        add_action('wp_login_failed', [__CLASS__, 'on_login_failed'], 10, 1);
        add_action('wp_login', [__CLASS__, 'on_login_success'], 10, 2);
    }

    private static function profile(): array {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        return $cfg['profiles'][$active] ?? [];
    }

    private static function ip_key(string $suffix): string {
        $ip = HCYB_Logger::client_ip() ?: 'unknown';
        return 'hcyb_login_' . $suffix . '_' . $ip;
    }

    public static function rate_limit_auth($user, $username, $password) {
        $p = self::profile();
        $login = $p['login'] ?? ['enabled'=>false];
        if (empty($login['enabled'])) return $user;

        $max = (int)($login['max_attempts'] ?? 8);
        $window = (int)($login['window_sec'] ?? 900);
        $lock = (int)($login['lock_sec'] ?? 1800);

        $lock_until = (int)HCYB_DB::kv_get(self::ip_key('lock_until'), 0);
        if ($lock_until && time() < $lock_until) {
            HCYB_Logger::event('med','login','locked',[
                'message'=>'Zablokowano logowanie (lockout aktywny)',
                'meta'=>['until'=>$lock_until, 'user'=>$username]
            ]);
            return new WP_Error('hcyb_locked', 'Zbyt wiele prób. Spróbuj ponownie później.');
        }

        // w oknie czasowym
        $bucket = HCYB_DB::kv_get(self::ip_key('bucket'), ['count'=>0,'start'=>time()]);
        if (!is_array($bucket) || !isset($bucket['count'],$bucket['start'])) {
            $bucket = ['count'=>0,'start'=>time()];
        }

        if (time() - (int)$bucket['start'] > $window) {
            $bucket = ['count'=>0,'start'=>time()];
        }

        if ((int)$bucket['count'] >= $max) {
            $until = time() + $lock;
            HCYB_DB::kv_set(self::ip_key('lock_until'), $until, $lock);
            HCYB_Logger::event('high','login','locked',[
                'message'=>'Lockout: zbyt wiele prób logowania',
                'meta'=>['max'=>$max,'window'=>$window,'lock'=>$lock,'user'=>$username]
            ]);
            return new WP_Error('hcyb_locked', 'Zbyt wiele prób. Spróbuj ponownie później.');
        }

        // zapis bucket z TTL = window
        HCYB_DB::kv_set(self::ip_key('bucket'), $bucket, $window);
        return $user;
    }

    public static function on_login_failed($username): void {
        $p = self::profile();
        $login = $p['login'] ?? ['enabled'=>false];
        if (empty($login['enabled'])) return;

        $window = (int)($login['window_sec'] ?? 900);

        $bucket = HCYB_DB::kv_get(self::ip_key('bucket'), ['count'=>0,'start'=>time()]);
        if (!is_array($bucket) || !isset($bucket['count'],$bucket['start'])) {
            $bucket = ['count'=>0,'start'=>time()];
        }
        if (time() - (int)$bucket['start'] > $window) {
            $bucket = ['count'=>0,'start'=>time()];
        }
        $bucket['count'] = (int)$bucket['count'] + 1;
        HCYB_DB::kv_set(self::ip_key('bucket'), $bucket, $window);

        HCYB_Logger::event('low','login','failed',[
            'message'=>'Nieudane logowanie',
            'meta'=>['user'=>$username,'count'=>$bucket['count']]
        ]);
    }

    public static function on_login_success($user_login, $user): void {
        // reset bucket po udanym logowaniu
        HCYB_DB::kv_set(self::ip_key('bucket'), ['count'=>0,'start'=>time()], 3600);
        HCYB_DB::kv_set(self::ip_key('lock_until'), 0, 3600);
        HCYB_Logger::event('low','login','success',[
            'message'=>'Udane logowanie',
            'user_id'=> is_object($user) ? (int)$user->ID : null
        ]);
    }
}
