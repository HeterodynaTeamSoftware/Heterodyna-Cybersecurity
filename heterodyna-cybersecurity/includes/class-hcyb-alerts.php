<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Alerts {
    public static function init(): void {
        // nic na starcie
    }

    public static function maybe_notify(string $level, string $category, string $action, array $ctx = []): void {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $profiles = $cfg['profiles'] ?? [];
        $p = $profiles[$active] ?? [];

        $alerts = $p['alerts'] ?? [];
        $enabled = (bool)($alerts['enabled'] ?? false);
        if (!$enabled) return;

        $min_level = (string)($alerts['min_level'] ?? 'high'); // high|med|low
        // UWAGA: nie używamy wp_options (get_option). Odbiorcy muszą być jawnie ustawieni w polityce.
        $emails_raw = (string)($alerts['emails'] ?? '');
        $emails = array_filter(array_map('trim', preg_split('/[;,\s]+/', $emails_raw) ?: []));
        if (!$emails) return;

        $cooldown_sec = (int)($alerts['cooldown_sec'] ?? 600);
        if ($cooldown_sec < 60) $cooldown_sec = 60;

        if (!self::level_meets($level, $min_level)) return;

        // anty-spam (globalny cooldown)
        $last = (int)HCYB_DB::kv_get('hcyb_alert_last', 0);
        if (time() - $last < $cooldown_sec) return;
        HCYB_DB::kv_set('hcyb_alert_last', time(), $cooldown_sec + 300);

        $ip = $ctx['ip'] ?? HCYB_Logger::client_ip();
        $path = $ctx['path'] ?? (isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '');
        $method = $ctx['method'] ?? ($_SERVER['REQUEST_METHOD'] ?? '');

        $subject = 'HCYB ALERT: ' . strtoupper($level) . ' • ' . $category . ' / ' . $action;
        $body = "Wykryto zdarzenie bezpieczeństwa.\n\n";
        $body .= "Poziom: $level\n";
        $body .= "Kategoria: $category\n";
        $body .= "Akcja: $action\n";
        $body .= "IP: " . ($ip ?: '-') . "\n";
        $body .= "Metoda: $method\n";
        $body .= "Ścieżka: $path\n";
        if (!empty($ctx['message'])) {
            $body .= "\nOpis: " . (string)$ctx['message'] . "\n";
        }
        $body .= "\nPanel: " . admin_url('admin.php?page=hcyb-events') . "\n";

        foreach ($emails as $to) {
            if (!is_email($to)) continue;
            wp_mail($to, $subject, $body);
        }
    }

    private static function level_meets(string $level, string $min): bool {
        $map = ['low'=>1,'med'=>2,'medium'=>2,'high'=>3,'critical'=>4];
        $l = $map[strtolower($level)] ?? 1;
        $m = $map[strtolower($min)] ?? 3;
        return $l >= $m;
    }
}
