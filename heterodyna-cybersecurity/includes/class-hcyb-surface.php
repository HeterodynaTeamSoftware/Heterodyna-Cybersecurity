<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Surface {

    /**
     * Skan ekspozycji z zewnątrz: sprawdza dostępność znanych wrażliwych ścieżek oraz podstawowe nagłówki.
     * Nie wykonuje ataków - tylko HEAD/GET i analiza kodów odpowiedzi.
     *
     * @param array $hosts Lista hostów (bez protokołu), np. ["example.com","sub.example.com"]
     * @return array Wyniki
     */
    public static function scan(array $hosts): array {
        $hosts = array_values(array_unique(array_filter(array_map('strtolower', array_map('trim', $hosts)))));
        if (!$hosts) {
            $hosts = [parse_url(home_url('/'), PHP_URL_HOST)];
        }

        $targets = self::default_targets();
        $results = [];
        foreach ($hosts as $host) {
            $base = (is_ssl() ? 'https://' : 'http://') . $host;
            $base = rtrim($base, '/');
            $site = [
                'host' => $host,
                'base' => $base,
                'items' => [],
                'headers' => [],
                'summary' => ['high'=>0,'med'=>0,'low'=>0,'info'=>0],
            ];

            // Nagłówki strony głównej
            $home = $base . '/';
            $head = self::http_head($home);
            $site['headers'] = self::analyze_headers($head);

            foreach ($targets as $t) {
                $url = $base . $t['path'];
                $item = [
                    'id' => $t['id'],
                    'name' => $t['name'],
                    'path' => $t['path'],
                    'method' => $t['method'],
                    'risk' => $t['risk'],
                    'expect' => $t['expect'],
                    'status' => null,
                    'note' => '',
                ];

                $resp = ($t['method'] === 'GET') ? self::http_get($url) : self::http_head($url);
                $code = (int) wp_remote_retrieve_response_code($resp);
                $item['status'] = $code;

                $item = self::classify($item, $resp);
                $site['items'][] = $item;

                $rk = $item['risk_effective'];
                if (!isset($site['summary'][$rk])) $site['summary'][$rk]=0;
                $site['summary'][$rk]++;

                // Loguj tylko rzeczy, które faktycznie są problemem
                if (in_array($rk, ['high','med'], true)) {
                    HCYB_Logger::event($rk, 'surface', 'exposed', [
                        'path' => $host . $t['path'],
                        'status' => $code,
                        'rule_id' => $t['id'],
                        'message' => $item['note'],
                    ]);
                }
            }

            $results[] = $site;
        }

        return [
            'generated_at_utc' => gmdate('Y-m-d H:i:s'),
            'hosts' => $hosts,
            'results' => $results,
        ];
    }

    private static function default_targets(): array {
        return [
            ['id'=>'install_php','name'=>'Instalator WordPress (install.php)','path'=>'/wp-admin/install.php','method'=>'HEAD','risk'=>'high','expect'=>'403/404'],
            ['id'=>'wp_install_php','name'=>'install.php w root','path'=>'/install.php','method'=>'HEAD','risk'=>'high','expect'=>'404'],
            ['id'=>'env','name'=>'Plik .env','path'=>'/.env','method'=>'HEAD','risk'=>'high','expect'=>'404'],
            ['id'=>'git_head','name'=>'.git/HEAD','path'=>'/.git/HEAD','method'=>'HEAD','risk'=>'high','expect'=>'404'],
            ['id'=>'debug_log','name'=>'debug.log','path'=>'/wp-content/debug.log','method'=>'HEAD','risk'=>'med','expect'=>'404'],
            ['id'=>'readme','name'=>'readme.html (WP)','path'=>'/readme.html','method'=>'HEAD','risk'=>'low','expect'=>'404'],
            ['id'=>'license','name'=>'license.txt (WP)','path'=>'/license.txt','method'=>'HEAD','risk'=>'low','expect'=>'404'],
            ['id'=>'users_rest','name'=>'REST users (public)','path'=>'/wp-json/wp/v2/users?per_page=1','method'=>'GET','risk'=>'med','expect'=>'401/403 lub brak danych'],
            ['id'=>'author_enum','name'=>'Enumeracja autora (?author=1)','path'=>'/?author=1','method'=>'HEAD','risk'=>'med','expect'=>'brak przekierowania do /author/'],
            ['id'=>'backup_zip','name'=>'Backup ZIP (częsty błąd)','path'=>'/backup.zip','method'=>'HEAD','risk'=>'high','expect'=>'404'],
            ['id'=>'backup_sql','name'=>'Backup SQL (częsty błąd)','path'=>'/backup.sql','method'=>'HEAD','risk'=>'high','expect'=>'404'],
            ['id'=>'db_sql','name'=>'Dump DB (db.sql)','path'=>'/db.sql','method'=>'HEAD','risk'=>'high','expect'=>'404'],
        ];
    }

    private static function http_head(string $url) {
        return wp_remote_head($url, [
            'timeout' => 10,
            'redirection' => 2,
            'user-agent' => 'HeterodynaCybersecurity/1.0',
        ]);
    }

    private static function http_get(string $url) {
        return wp_remote_get($url, [
            'timeout' => 10,
            'redirection' => 2,
            'user-agent' => 'HeterodynaCybersecurity/1.0',
        ]);
    }

    private static function analyze_headers($resp): array {
        $headers = [];
        if (is_wp_error($resp)) {
            return ['ok'=>false,'note'=>'Błąd pobierania nagłówków: ' . $resp->get_error_message()];
        }
        $h = wp_remote_retrieve_headers($resp);
        $get = function($k) use ($h) {
            $v = $h[$k] ?? $h[strtolower($k)] ?? null;
            return is_array($v) ? implode(';', $v) : (string)$v;
        };

        $need = [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => '(np. strict-origin-when-cross-origin)',
        ];

        $missing = [];
        foreach ($need as $k=>$ex) {
            $v = $get($k);
            if (!$v) $missing[] = $k;
            $headers[$k] = $v ?: '';
        }

        $headers['Strict-Transport-Security'] = $get('Strict-Transport-Security');
        $headers['Content-Security-Policy'] = $get('Content-Security-Policy');
        $headers['X-Frame-Options'] = $get('X-Frame-Options');

        return [
            'ok' => true,
            'missing' => $missing,
            'values' => $headers,
        ];
    }

    private static function classify(array $item, $resp): array {
        $code = (int)($item['status'] ?? 0);

        // domyślnie info jeśli brak danych
        $item['risk_effective'] = 'info';
        $item['note'] = 'Brak danych.';
        if (is_wp_error($resp)) {
            $item['risk_effective'] = 'info';
            $item['note'] = 'Błąd HTTP: ' . $resp->get_error_message();
            return $item;
        }

        // heurystyka: 200/206 = exposed, 301/302 też może oznaczać ekspozycję (np. /author/)
        if ($code >= 200 && $code < 300) {
            $item['risk_effective'] = $item['risk'];
            $item['note'] = 'Zasób dostępny (HTTP ' . $code . ').';
        } elseif (in_array($code, [301,302,307,308], true)) {
            $loc = wp_remote_retrieve_header($resp, 'location');
            $loc = is_array($loc) ? ($loc[0] ?? '') : (string)$loc;
            // author enum: przekierowanie do /author/ jest sygnałem
            if ($item['id'] === 'author_enum' && stripos($loc, '/author/') !== false) {
                $item['risk_effective'] = 'med';
                $item['note'] = 'Przekierowanie do profilu autora (' . ($loc ?: 'location') . ').';
            } else {
                $item['risk_effective'] = 'low';
                $item['note'] = 'Przekierowanie (HTTP ' . $code . ').';
            }
        } elseif (in_array($code, [401,403,404], true)) {
            $item['risk_effective'] = 'info';
            $item['note'] = 'OK (HTTP ' . $code . ' - niedostępne).';
        } else {
            $item['risk_effective'] = 'low';
            $item['note'] = 'Nietypowy kod (HTTP ' . $code . ').';
        }

        // REST users: 200 z listą -> med/high
        if ($item['id'] === 'users_rest') {
            if ($code >= 200 && $code < 300) {
                $body = wp_remote_retrieve_body($resp);
                if (is_string($body) && strlen($body) > 5 && strpos($body, 'slug') !== false) {
                    $item['risk_effective'] = 'med';
                    $item['note'] = 'Lista użytkowników zwrócona przez REST (publiczna).';
                } else {
                    $item['risk_effective'] = 'low';
                    $item['note'] = 'REST odpowiada (sprawdź ręcznie).';
                }
            } elseif (in_array($code, [401,403], true)) {
                $item['risk_effective'] = 'info';
                $item['note'] = 'OK (REST users chronione).';
            }
        }

        return $item;
    }
}
