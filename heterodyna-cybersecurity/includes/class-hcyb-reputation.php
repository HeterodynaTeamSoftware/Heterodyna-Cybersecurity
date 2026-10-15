<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Reputation {

    public static function init(): void {
        // brak hooków globalnych; wywoływane na żądanie (WAF/panel)
    }

    public static function is_private_ip(string $ip): bool {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = ip2long($ip);
            $private = [
                [ip2long('10.0.0.0'), ip2long('10.255.255.255')],
                [ip2long('172.16.0.0'), ip2long('172.31.255.255')],
                [ip2long('192.168.0.0'), ip2long('192.168.255.255')],
                [ip2long('127.0.0.0'), ip2long('127.255.255.255')],
            ];
            foreach ($private as $r) {
                if ($long >= $r[0] && $long <= $r[1]) return true;
            }
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // link-local / loopback / unique local
            return (strpos($ip, 'fe80:') === 0) || ($ip === '::1') || (strpos($ip, 'fc') === 0) || (strpos($ip, 'fd') === 0);
        }
        return false;
    }

    /**
     * Zwraca rekord reputacji z cache lub tworzy nowy (heurystyczny).
     * Provider domyślny: local_heuristic (bez zewnętrznych API).
     */
    public static function get_or_fetch(string $ip, string $provider = 'local_heuristic'): array {
        $ip = trim($ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['ip' => $ip, 'provider' => $provider, 'risk_score' => null, 'country' => null, 'asn' => null, 'org' => null, 'raw_json' => null];
        }

        $cached = HCYB_DB::ip_cache_get($ip, $provider);
        if ($cached) return $cached;

        $data = self::build_heuristic($ip);
        $ttl = (int) (HCYB_DB::kv_get('rep_ttl', 7 * 24 * 3600)); // 7 dni
        $expires = gmdate('Y-m-d H:i:s', time() + $ttl);

        HCYB_DB::ip_cache_set($ip, $provider, $data['country'], $data['asn'], $data['org'], $data['risk_score'], $data['raw_json'], $expires);

        $cached2 = HCYB_DB::ip_cache_get($ip, $provider);
        return $cached2 ?: array_merge(['ip'=>$ip,'provider'=>$provider], $data);
    }

    private static function build_heuristic(string $ip): array {
        if (self::is_private_ip($ip)) {
            return [
                'country' => 'PRIVATE',
                'asn' => 'LOCAL',
                'org' => 'Sieć prywatna/localhost',
                'risk_score' => 0,
                'raw_json' => wp_json_encode(['flags'=>['private'=>true], 'method'=>'heuristic'])
            ];
        }

        // Prosta heurystyka: domyślnie niski/średni wynik, dopóki nie podłączysz providerów.
        // Cel: dać użytkową funkcję + miejsce na integracje.
        $risk = 15;

        // Drobne sygnały: brak UA bywa podejrzany (ale nie zawsze).
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (trim($ua) === '') $risk += 15;

        // Nietypowe metody też podbijają ryzyko.
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if (!in_array($method, ['GET','POST','HEAD','PUT','DELETE','OPTIONS'], true)) $risk += 20;

        $risk = max(0, min(100, $risk));

        return [
            'country' => null,
            'asn' => null,
            'org' => null,
            'risk_score' => $risk,
            'raw_json' => wp_json_encode(['flags'=>['public'=>true], 'method'=>'heuristic', 'ua_empty'=>trim($ua)==='', 'http_method'=>$method])
        ];
    }

    public static function should_block(int $risk_score, array $profile): bool {
        $rep = $profile['ip_reputation'] ?? [];
        if (empty($rep['enabled'])) return false;
        $threshold = (int)($rep['block_threshold'] ?? 80);
        return $risk_score >= $threshold;
    }
}
