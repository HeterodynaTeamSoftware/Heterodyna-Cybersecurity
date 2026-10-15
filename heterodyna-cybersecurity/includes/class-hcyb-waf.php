<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_WAF {

    public static function init(): void {
        add_action('init', [__CLASS__, 'handle_early'], 0);
    }

    public static function handle_early(): void {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $profile = ($cfg['profiles'][$active] ?? null);
        if (!$profile) return;

        $waf = $profile['waf'] ?? ['enabled' => false];
        if (empty($waf['enabled'])) return;

        // monitor | simulate | block
        // simulate = loguj "co by było zablokowane" bez blokowania
        $mode = $waf['mode'] ?? 'monitor';
        $level = $waf['block_level'] ?? 'low'; // low|med|high

        // Tryb kryzysowy: wymusza skuteczniejsze parametry ochrony.
        if (class_exists('HCYB_Emergency')) {
            HCYB_Emergency::apply_overrides($profile, $waf, $mode, $level);
        }

        $req_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '/';
        $path = parse_url($req_uri, PHP_URL_PATH) ?: '/';
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

        $ip = HCYB_Logger::client_ip() ?: 'unknown';

        // IP allow/deny
        $ip_allow = array_values(array_filter(array_map('trim', (array)($waf['ip_allow'] ?? []))));
        $ip_deny  = array_values(array_filter(array_map('trim', (array)($waf['ip_deny'] ?? []))));
        if (in_array($ip, $ip_allow, true)) {
            return; // zawsze przepuszczaj allowlist
        }
        if (in_array($ip, $ip_deny, true)) {
            // denylist: zawsze loguj, blokuj tylko w trybie block
            self::log_hit($mode === 'block' ? 'high' : 'med', 'waf', $mode === 'block' ? 'blocked' : 'detected', [
                'rule_id' => 'WAF-IP-DENY',
                'message' => 'IP na denyliście',
                'meta' => ['ip' => $ip],
                'path' => $req_uri,
                'method' => $method,
                'status' => $mode === 'block' ? 403 : 200,
            ]);
            if ($mode === 'block') {
                self::deny_403();
            }
            return;
        }


        // Reputacja IP (heurystyka/local cache). Działa niezależnie od WordPress.
        $rep_provider = $profile['ip_reputation']['provider'] ?? 'local_heuristic';
        $rep = HCYB_Reputation::get_or_fetch($ip, $rep_provider);
        $rep_risk = isset($rep['risk_score']) ? (int)$rep['risk_score'] : -1;

        if ($rep_risk >= 0 && HCYB_Reputation::should_block($rep_risk, $profile)) {
            $action = ($mode === 'block') ? 'blocked' : (($mode === 'simulate') ? 'would_block' : 'detected');
            self::log_hit($mode === 'block' ? 'high' : 'med', 'waf', $action, [
                'rule_id' => 'WAF-IP-REPUTATION',
                'message' => 'Blokada po reputacji IP (próg profilu)',
                'meta' => [
                    'ip' => $ip,
                    'risk_score' => $rep_risk,
                    'country' => $rep['country'] ?? null,
                    'asn' => $rep['asn'] ?? null,
                    'org' => $rep['org'] ?? null,
                    'provider' => $rep_provider,
                ],
                'path' => $req_uri,
                'method' => $method,
                'status' => $mode === 'block' ? 403 : 200,
            ]);
            if ($mode === 'block') {
                self::deny_403();
            }
            // monitor/symulacja: nie blokuje
        }


        // Rate limiting per endpoint
        $endpoint_hit = self::match_endpoint($path);
        if ($endpoint_hit) {
            $rl = (array)($waf['rate_limits'][$endpoint_hit] ?? []);
            if (!empty($rl['enabled'])) {
                $rl_res = self::rate_limit_check($endpoint_hit, $ip, $method, $rl, $waf);
                if ($rl_res['hit']) {
                    $action = ($mode === 'block') ? 'blocked' : (($mode === 'simulate') ? 'would_block' : 'detected');
                    $lvl = ($mode === 'block') ? 'high' : 'med';
                    self::log_hit($lvl, 'waf', $action, [
                        'rule_id' => 'WAF-RL-' . strtoupper($endpoint_hit),
                        'message' => $rl_res['message'],
                        'meta' => $rl_res['meta'],
                        'path' => $req_uri,
                        'method' => $method,
                        'status' => ($mode === 'block') ? 429 : 200,
                    ]);
                    if ($mode === 'block') {
                        status_header(429);
                        header('Content-Type: text/plain; charset=utf-8');
                        echo "429 Za dużo żądań. Ograniczenie tempa (Heterodyna Cybersecurity).\n";
                        exit;
                    }
                    // monitor/simulate nie blokuje
                }
            }
        }

        if (self::is_whitelisted($profile, $path, $method)) return;

        $hit = self::detect($req_uri, $method, $level);
        if (!$hit) return;

        $action = ($mode === 'block') ? 'blocked' : (($mode === 'simulate') ? 'would_block' : 'detected');
        self::log_hit(
            $mode === 'block' ? 'high' : 'med',
            'waf',
            $action,
            [
                'rule_id' => $hit['rule'],
                'message' => $hit['msg'],
                'meta' => ['pattern' => $hit['pattern'], 'level' => $level],
                'path' => $req_uri,
                'method' => $method,
                'status' => $mode === 'block' ? 403 : 200,
            ]
        );

        if ($mode === 'block') {
            self::deny_403();
        }
    }

    private static function deny_403(): void {
        status_header(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "403 Zabronione. Żądanie zostało zablokowane przez Heterodyna Cybersecurity (WAF).\n";
        exit;
    }

    private static function log_hit(string $level, string $category, string $action, array $data): void {
        HCYB_Logger::event($level, $category, $action, $data);
    }

    private static function match_endpoint(string $path): ?string {
        if ($path === '/wp-login.php') return 'wp_login';
        if ($path === '/xmlrpc.php') return 'xmlrpc';
        if (str_starts_with($path, '/wp-json/')) return 'rest';
        if ($path === '/wp-admin/admin-ajax.php') return 'admin_ajax';
        return null;
    }

    private static function rate_limit_check(string $endpoint, string $ip, string $method, array $rl, array $waf): array {
        $max = (int)($rl['max'] ?? 60);
        $window = (int)($rl['window_sec'] ?? 60);
        $lock = (int)($rl['block_sec'] ?? 300);
        if ($max < 1) $max = 1;
        if ($window < 5) $window = 5;
        if ($lock < 5) $lock = 5;

        $only = array_values(array_filter(array_map('strtoupper', (array)($rl['only_methods'] ?? []))));
        if (!empty($only) && !in_array($method, $only, true)) {
            return ['hit'=>false, 'message'=>'', 'meta'=>[]];
        }

        $fingerprint_on = !empty($waf['fingerprint']);
        $fp = $fingerprint_on ? self::fingerprint($ip) : $ip;

        $k_lock = 'hcyb_rl_lock_' . $endpoint . '_' . $fp;
        $k_bucket = 'hcyb_rl_bucket_' . $endpoint . '_' . $fp;

        $lock_until = (int)HCYB_DB::kv_get($k_lock, 0);
        if ($lock_until && time() < $lock_until) {
            return [
                'hit' => true,
                'message' => 'Limit żądań: aktywny lockout',
                'meta' => ['endpoint'=>$endpoint,'until'=>$lock_until,'max'=>$max,'window'=>$window,'lock'=>$lock,'fp'=>$fp]
            ];
        }

        $bucket = HCYB_DB::kv_get($k_bucket, ['count'=>0,'start'=>time()]);
        if (!is_array($bucket) || !isset($bucket['count'],$bucket['start'])) {
            $bucket = ['count'=>0,'start'=>time()];
        }
        if (time() - (int)$bucket['start'] > $window) {
            $bucket = ['count'=>0,'start'=>time()];
        }
        $bucket['count'] = (int)$bucket['count'] + 1;
        HCYB_DB::kv_set($k_bucket, $bucket, $window);

        if ((int)$bucket['count'] > $max) {
            $until = time() + $lock;
            HCYB_DB::kv_set($k_lock, $until, $lock);
            return [
                'hit' => true,
                'message' => 'Limit żądań: przekroczono próg',
                'meta' => ['endpoint'=>$endpoint,'count'=>$bucket['count'],'max'=>$max,'window'=>$window,'lock'=>$lock,'fp'=>$fp]
            ];
        }

        return ['hit'=>false, 'message'=>'', 'meta'=>['endpoint'=>$endpoint,'count'=>$bucket['count'],'max'=>$max,'window'=>$window,'fp'=>$fp]];
    }

    private static function fingerprint(string $ip): string {
        $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
        return substr(hash('sha256', $ip . '|' . $ua), 0, 24);
    }

    private static function is_whitelisted(array $profile, string $path, string $method): bool {
        $allow = $profile['allow'] ?? [];
        $paths = $allow['paths_allow'] ?? [];
        $uploads_allow = !empty($allow['uploads_allow']);

        // Nie blokuj multimediów (GET/HEAD)
        if ($uploads_allow && in_array($method, ['GET','HEAD'], true)) {
            if (str_starts_with($path, '/wp-content/uploads/')) return true;
            if (str_starts_with($path, '/wp-includes/images/')) return true;
        }

        // Ścieżki allowlist
        foreach ((array)$paths as $p) {
            $p = trim((string)$p);
            if ($p === '') continue;
            if (str_starts_with($path, $p)) return true;
        }

        // WP core: favicon, robots, sitemapy
        if (in_array($path, ['/favicon.ico','/robots.txt','/sitemap.xml'], true)) return true;

        return false;
    }

    private static function detect(string $uri, string $method, string $level): ?array {
        $q = $uri;
        $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));

        $rules = [];

        // zawsze
        $rules[] = ['rule'=>'WAF-URI-LFI', 'pattern'=>'/(\.{2}\/|\/\.\.\/|etc\/passwd|proc\/self\/environ)/i', 'msg'=>'Podejrzenie LFI/path traversal'];
        $rules[] = ['rule'=>'WAF-URI-RFI', 'pattern'=>'/(?:https?:\/\/).*(?:\.php|\bbase64\b|\bdata:)/i', 'msg'=>'Podejrzenie RFI / próba zdalnego include'];
        $rules[] = ['rule'=>'WAF-URI-XSS', 'pattern'=>'/(<script\b|%3Cscript|onerror=|onload=|javascript:)/i', 'msg'=>'Podejrzenie XSS'];
        $rules[] = ['rule'=>'WAF-URI-SQLI', 'pattern'=>'/(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b|\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bINFORMATION_SCHEMA\b)/i', 'msg'=>'Podejrzenie SQLi'];
        $rules[] = ['rule'=>'WAF-URI-PHP', 'pattern'=>'/(\bphpinfo\b|\beval\s*\(|\bassert\s*\(|\bgzinflate\s*\(|\bbase64_decode\s*\()/i', 'msg'=>'Podejrzenie webshell/szkodliwego payloadu'];

        if ($level !== 'low') {
            $rules[] = ['rule'=>'WAF-URI-DANG', 'pattern'=>'/(\bwp-config\.php\b|\.env\b|\.git\b|backup|\.sql\b|\.zip\b)/i', 'msg'=>'Podejrzenie próby dostępu do wrażliwych plików'];
            $rules[] = ['rule'=>'WAF-UA-BOT', 'pattern'=>'/(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster)/i', 'msg'=>'Podejrzenie skanera/automatu (User-Agent)'];
        }

        if ($level === 'high') {
            $rules[] = ['rule'=>'WAF-URI-ENC', 'pattern'=>'/(%00|%2e%2e%2f|%5c%5c|%27%20or%20%271%27%3d%271|\bOR\b\s+\d+=\d+)/i', 'msg'=>'Wysokie ryzyko (encodowane payloady)'];
        }

        foreach ($rules as $r) {
            if (preg_match($r['pattern'], $q) === 1) {
                return ['rule'=>$r['rule'], 'pattern'=>$r['pattern'], 'msg'=>$r['msg']];
            }
        }

        // UA detekcja tylko dla med/high
        if ($level !== 'low') {
            if ($ua && preg_match('/(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster)/i', $ua)) {
                return ['rule'=>'WAF-UA-BOT', 'pattern'=>'/botua/', 'msg'=>'Podejrzenie skanera/automatu (User-Agent)'];
            }
        }

        return null;
    }
}
