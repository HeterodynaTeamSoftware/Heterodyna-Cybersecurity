<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Admin {

    public static function init(): void {
        add_action('admin_menu', [__CLASS__, 'menu']);
        add_action('admin_enqueue_scripts', [__CLASS__, 'assets']);
        add_action('wp_ajax_hcyb_save_settings', [__CLASS__, 'ajax_save_settings']);
        add_action('wp_ajax_hcyb_scan_baseline', [__CLASS__, 'ajax_baseline']);
        add_action('wp_ajax_hcyb_scan_quick', [__CLASS__, 'ajax_scan_quick']);
        add_action('wp_ajax_hcyb_fullscan_start', [__CLASS__, 'ajax_fullscan_start']);
        add_action('wp_ajax_hcyb_fullscan_tick', [__CLASS__, 'ajax_fullscan_tick']);
        add_action('wp_ajax_hcyb_fullscan_status', [__CLASS__, 'ajax_fullscan_status']);
        add_action('wp_ajax_hcyb_fullscan_stop', [__CLASS__, 'ajax_fullscan_stop']);
        add_action('wp_ajax_hcyb_check_ip', [__CLASS__, 'ajax_check_ip']);
        add_action('wp_ajax_hcyb_save_reputation', [__CLASS__, 'ajax_save_reputation']);
        add_action('wp_ajax_hcyb_export_config', [__CLASS__, 'ajax_export']);
        add_action('wp_ajax_hcyb_import_config', [__CLASS__, 'ajax_import']);
        add_action('wp_ajax_hcyb_policy_export_signed', [__CLASS__, 'ajax_policy_export_signed']);
        add_action('wp_ajax_hcyb_policy_import_signed', [__CLASS__, 'ajax_policy_import_signed']);
        add_action('wp_ajax_hcyb_policy_list_versions', [__CLASS__, 'ajax_policy_list_versions']);
        add_action('wp_ajax_hcyb_policy_diff', [__CLASS__, 'ajax_policy_diff']);
        add_action('wp_ajax_hcyb_policy_rollback', [__CLASS__, 'ajax_policy_rollback']);
        add_action('wp_ajax_hcyb_generate_mu_loader', [__CLASS__, 'ajax_generate_mu_loader']);
        add_action('wp_ajax_hcyb_surface_scan', [__CLASS__, 'ajax_surface_scan']);
        add_action('wp_ajax_hcyb_emergency_enable', [__CLASS__, 'ajax_emergency_enable']);
        add_action('wp_ajax_hcyb_emergency_disable', [__CLASS__, 'ajax_emergency_disable']);
    }

    public static function menu(): void {
        add_menu_page(
            'Heterodyna Cybersecurity',
            'Heterodyna Cybersecurity',
            'manage_options',
            'hcyb',
            [__CLASS__, 'page_dashboard'],
            'dashicons-shield-alt',
            58
        );

        add_submenu_page('hcyb', 'Dashboard', 'Dashboard', 'manage_options', 'hcyb', [__CLASS__, 'page_dashboard']);
        add_submenu_page('hcyb', 'Polityki', 'Polityki', 'manage_options', 'hcyb-policies', [__CLASS__, 'page_policies']);
        add_submenu_page('hcyb', 'Firewall (WAF)', 'Firewall (WAF)', 'manage_options', 'hcyb-waf', [__CLASS__, 'page_waf']);
        add_submenu_page('hcyb', 'Twardnienie WP', 'Twardnienie WP', 'manage_options', 'hcyb-hardening', [__CLASS__, 'page_hardening']);
        add_submenu_page('hcyb', 'Skaner', 'Skaner', 'manage_options', 'hcyb-scanner', [__CLASS__, 'page_scanner']);
        add_submenu_page('hcyb', 'Ekspozycja', 'Ekspozycja', 'manage_options', 'hcyb-surface', [__CLASS__, 'page_surface']);
        add_submenu_page('hcyb', 'Reputacja IP', 'Reputacja IP', 'manage_options', 'hcyb-reputation', [__CLASS__, 'page_reputation']);
        add_submenu_page('hcyb', 'Raporty', 'Raporty', 'manage_options', 'hcyb-reports', [__CLASS__, 'page_reports']);
        add_submenu_page('hcyb', 'Zdarzenia', 'Zdarzenia', 'manage_options', 'hcyb-events', [__CLASS__, 'page_events']);
        add_submenu_page('hcyb', 'Ustawienia', 'Ustawienia', 'manage_options', 'hcyb-settings', [__CLASS__, 'page_settings']);
    }

    public static function page_reports(): void {
        if (!current_user_can('manage_options')) return;
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $profiles = $cfg['profiles'] ?? [];
        $p = $profiles[$active] ?? [];

        $days = isset($_POST['hcyb_rep_days']) ? max(1, min(90, (int)$_POST['hcyb_rep_days'])) : 7;
        $msg = '';

        // zapis alertów
        if (!empty($_POST['hcyb_save_alerts']) && check_admin_referer('hcyb_reports_save')) {
            $alerts_enabled = !empty($_POST['hcyb_alerts_enabled']);
            $alerts_emails = sanitize_textarea_field($_POST['hcyb_alerts_emails'] ?? '');
            $alerts_min = sanitize_text_field($_POST['hcyb_alerts_min'] ?? 'high');
            $alerts_cd = (int)($_POST['hcyb_alerts_cd'] ?? 600);
            if ($alerts_cd < 60) $alerts_cd = 60;
            $p['alerts'] = [
                'enabled' => $alerts_enabled,
                'emails' => $alerts_emails,
                'min_level' => in_array($alerts_min, ['low','med','high'], true) ? $alerts_min : 'high',
                'cooldown_sec' => $alerts_cd,
            ];
            $profiles[$active] = $p;
            $cfg['profiles'] = $profiles;
            HCYB_DB::set_config('hcyb', $cfg);
            HCYB_Policies::create_snapshot('Zapis alertów (Raporty)', get_current_user_id(), 'admin');
            $msg = 'Zapisano ustawienia alertów.';
        }

        // zapis raportu tygodniowego
        if (!empty($_POST['hcyb_save_digest']) && check_admin_referer('hcyb_digest_save')) {
            $digest_enabled = !empty($_POST['hcyb_digest_enabled']);
            $digest_emails = sanitize_textarea_field($_POST['hcyb_digest_emails'] ?? '');
            $digest_dow = (int)($_POST['hcyb_digest_dow'] ?? 1);
            $digest_hour = (int)($_POST['hcyb_digest_hour'] ?? 9);
            $digest_days = (int)($_POST['hcyb_digest_days'] ?? 7);
            if ($digest_dow < 1 || $digest_dow > 7) $digest_dow = 1;
            if ($digest_hour < 0 || $digest_hour > 23) $digest_hour = 9;
            if ($digest_days < 1 || $digest_days > 30) $digest_days = 7;
            $p['digest'] = [
                'enabled' => $digest_enabled,
                'emails' => $digest_emails,
                'day_of_week' => $digest_dow,
                'hour' => $digest_hour,
                'period_days' => $digest_days,
            ];
            $profiles[$active] = $p;
            $cfg['profiles'] = $profiles;
            HCYB_DB::set_config('hcyb', $cfg);
            HCYB_Policies::create_snapshot('Zapis raportu tygodniowego', get_current_user_id(), 'admin');
            $msg = 'Zapisano ustawienia raportu tygodniowego.';
        }

        // test raportu tygodniowego
        if (!empty($_POST['hcyb_send_digest_test']) && check_admin_referer('hcyb_digest_test')) {
            $ok = class_exists('HCYB_Digest') ? HCYB_Digest::send_test_now($days) : false;
            $msg = $ok ? 'Wysłano testowy raport.' : 'Nie udało się wysłać testu (sprawdź odbiorców).';
        }

        // prywatność IP
        if (!empty($_POST['hcyb_save_privacy']) && check_admin_referer('hcyb_privacy_save')) {
            $mode = sanitize_text_field($_POST['hcyb_ip_mode'] ?? 'full');
            if (!in_array($mode, ['full','masked','hash','off'], true)) $mode = 'full';
            $p['privacy'] = ['ip_mode' => $mode];
            $profiles[$active] = $p;
            $cfg['profiles'] = $profiles;
            HCYB_DB::set_config('hcyb', $cfg);
            HCYB_Policies::create_snapshot('Zapis prywatności IP', get_current_user_id(), 'admin');
            $msg = 'Zapisano ustawienia prywatności IP.';
        }

        // manualny cleanup
        if (!empty($_POST['hcyb_cleanup_now']) && check_admin_referer('hcyb_reports_cleanup')) {
            $ret = (int)($p['retention_days'] ?? 30);
            $deleted = HCYB_Logger::cleanup_events_older_than_days($ret);
            $msg = 'Wyczyszczono zdarzenia: ' . (int)$deleted;
        }

        $alerts = $p['alerts'] ?? ['enabled'=>false,'emails'=>'','min_level'=>'high','cooldown_sec'=>600];
        $digest = $p['digest'] ?? ['enabled'=>false,'emails'=>'','day_of_week'=>1,'hour'=>9,'period_days'=>7];
        $privacy = $p['privacy'] ?? ['ip_mode'=>'full'];
        $ret = (int)($p['retention_days'] ?? 30);
        if ($ret < 7) $ret = 7;

        echo '<div class="wrap">';
        echo '<h1>Raporty</h1>';
        if ($msg) echo '<div class="notice notice-success"><p>' . esc_html($msg) . '</p></div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Raport zdarzeń</h2>';
        echo '<form method="post">';
        echo '<p>Okres (dni): <input type="number" name="hcyb_rep_days" min="1" max="90" value="' . (int)$days . '"> <button class="button">Generuj</button></p>';
        $html = HCYB_Reports::render_html($days);
        echo $html;
        echo '</form>';
        echo '</div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Alerty e-mail</h2>';
        echo '<form method="post">';
        wp_nonce_field('hcyb_reports_save');
        echo '<p><label><input type="checkbox" name="hcyb_alerts_enabled" ' . (!empty($alerts['enabled']) ? 'checked' : '') . '> Włącz alerty</label></p>';
        echo '<p>Odbiorcy (e-mail, rozdziel przecinkiem/spacją):<br>';
        echo '<textarea name="hcyb_alerts_emails" rows="2" style="width:100%">' . esc_textarea((string)($alerts['emails'] ?? '')) . '</textarea></p>';
        echo '<p>Minimalny poziom: <select name="hcyb_alerts_min">';
        foreach (['high'=>'HIGH','med'=>'MED','low'=>'LOW'] as $k=>$label) {
            $sel = ((string)($alerts['min_level'] ?? 'high') === $k) ? 'selected' : '';
            echo '<option value="' . esc_attr($k) . '" ' . $sel . '>' . esc_html($label) . '</option>';
        }
        echo '</select></p>';
        echo '<p>Cooldown (sekundy, min 60): <input type="number" name="hcyb_alerts_cd" min="60" value="' . (int)($alerts['cooldown_sec'] ?? 600) . '"></p>';
        echo '<p><button class="button button-primary" name="hcyb_save_alerts" value="1">Zapisz</button></p>';
        echo '</form>';
        echo '</div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Raport tygodniowy (automatyczny)</h2>';
        echo '<form method="post">';
        wp_nonce_field('hcyb_digest_save');
        echo '<p><label><input type="checkbox" name="hcyb_digest_enabled" ' . (!empty($digest['enabled']) ? 'checked' : '') . '> Włącz raport tygodniowy</label></p>';
        echo '<p>Odbiorcy (e-mail, rozdziel przecinkiem/spacją):<br>';
        echo '<textarea name="hcyb_digest_emails" rows="2" style="width:100%">' . esc_textarea((string)($digest['emails'] ?? '')) . '</textarea></p>';
        echo '<p>Dzień tygodnia: <select name="hcyb_digest_dow">';
        $dows = [1=>'Poniedziałek',2=>'Wtorek',3=>'Środa',4=>'Czwartek',5=>'Piątek',6=>'Sobota',7=>'Niedziela'];
        foreach ($dows as $k=>$label) {
            $sel = ((int)($digest['day_of_week'] ?? 1) === (int)$k) ? 'selected' : '';
            echo '<option value="' . (int)$k . '" ' . $sel . '>' . esc_html($label) . '</option>';
        }
        echo '</select></p>';
        echo '<p>Godzina (0–23): <input type="number" name="hcyb_digest_hour" min="0" max="23" value="' . (int)($digest['hour'] ?? 9) . '"></p>';
        echo '<p>Okres raportu (dni, 1–30): <input type="number" name="hcyb_digest_days" min="1" max="30" value="' . (int)($digest['period_days'] ?? 7) . '"></p>';
        echo '<p><button class="button button-primary" name="hcyb_save_digest" value="1">Zapisz</button></p>';
        echo '</form>';
        echo '<form method="post" style="margin-top:8px">';
        wp_nonce_field('hcyb_digest_test');
        echo '<p><button class="button" name="hcyb_send_digest_test" value="1">Wyślij test teraz</button></p>';
        echo '<p class="hcyb-muted">Wysyłka działa bez WP-Cron – wtyczka wysyła raport przy normalnym ruchu (tick).</p>';
        echo '</form>';
        echo '</div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Prywatność IP (anonimizacja)</h2>';
        echo '<form method="post">';
        wp_nonce_field('hcyb_privacy_save');
        echo '<p>Tryb zapisu IP: <select name="hcyb_ip_mode">';
        $modes = ['full'=>'Pełne IP (domyślnie)','masked'=>'Maskuj (IPv4 /24, IPv6 /48)','hash'=>'Hash (anonimowy identyfikator)','off'=>'Nie zapisuj IP'];
        foreach ($modes as $k=>$label) {
            $sel = ((string)($privacy['ip_mode'] ?? 'full') === $k) ? 'selected' : '';
            echo '<option value="' . esc_attr($k) . '" ' . $sel . '>' . esc_html($label) . '</option>';
        }
        echo '</select></p>';
        echo '<p class="hcyb-muted">Zmiana działa dla nowych zdarzeń. Stare wpisy w logach zostają bez zmian.</p>';
        echo '<p><button class="button button-primary" name="hcyb_save_privacy" value="1">Zapisz</button></p>';
        echo '</form>';
        echo '</div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Retencja logów</h2>';
        echo '<p>Aktywna polityka trzyma logi przez: <strong>' . (int)$ret . ' dni</strong>. (Ustaw w Polityki → edycja profilu)</p>';
        echo '<form method="post">';
        wp_nonce_field('hcyb_reports_cleanup');
        echo '<p><button class="button" name="hcyb_cleanup_now" value="1">Wyczyść teraz</button></p>';
        echo '</form>';
        echo '</div>';

        echo '</div>';
    }

    public static function assets($hook): void {
        if (strpos((string)$hook, 'hcyb') === false) return;
        wp_enqueue_style('hcyb-admin', HCYB_URL . 'assets/admin.css', [], HCYB_VERSION);
        wp_enqueue_script('hcyb-admin', HCYB_URL . 'assets/admin.js', ['jquery'], HCYB_VERSION, true);
        wp_localize_script('hcyb-admin', 'HCYB', [
            'ajax' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('hcyb_nonce'),
        ]);
    }

    private static function get_cfg(): array {
        return HCYB_DB::get_config('hcyb', []);
    }

    private static function save_cfg(array $cfg): bool {
        return HCYB_DB::set_config('hcyb', $cfg);
    }

    public static function page_dashboard(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $waf_mode = $p['waf']['mode'] ?? 'monitor';
        $waf_on = !empty($p['waf']['enabled']);

        echo '<div class="wrap hcyb">';
        echo '<h1>Heterodyna Cybersecurity</h1>';
        echo '<div class="hcyb-grid">';
        echo '<div class="hcyb-card"><h2>Stan ochrony</h2>';
        echo '<p><strong>Profil:</strong> ' . esc_html($p['name'] ?? $active) . '</p>';
        echo '<p><strong>WAF:</strong> ' . ($waf_on ? ('ON (' . esc_html($waf_mode) . ')') : 'OFF') . '</p>';
        echo '<p><strong>Nagłówki:</strong> ' . (!empty($p['headers']['enabled']) ? 'ON' : 'OFF') . '</p>';
        echo '<p><strong>Hardening:</strong> ' . (!empty($p['hardening']) ? 'ON' : 'OFF') . '</p>';
        echo '<p class="hcyb-muted">Tip: Najpierw włącz tryb „Monitoruj” na 24h, potem dopiero „Blokuj”.</p>';
        echo '</div>';

        echo '<div class="hcyb-card"><h2>Szybkie akcje</h2>';
        echo '<p><button class="button button-primary hcyb-set-profile" data-profile="domyslny">Włącz profil domyślny</button> ';
        echo '<button class="button hcyb-set-profile" data-profile="twardy">Włącz profil twardy</button></p>';
        echo '<p><button class="button hcyb-baseline">Utwórz baseline skanera</button> ';
        echo '<button class="button hcyb-scan-quick">Skan szybki</button></p>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '</div>';

        // Tryb kryzysowy
        $em_active = class_exists('HCYB_Emergency') ? HCYB_Emergency::is_active() : false;
        $em_until = class_exists('HCYB_Emergency') ? HCYB_Emergency::until_ts() : 0;
        echo '<div class="hcyb-card"><h2>Tryb kryzysowy</h2>';
        echo '<p><strong>Status:</strong> ' . ($em_active ? '<span class="hcyb-badge">AKTYWNY</span>' : '<span class="hcyb-muted">wyłączony</span>') . '</p>';
        if ($em_active && $em_until) {
            echo '<p>Do: <code>' . esc_html(date('Y-m-d H:i:s', $em_until)) . '</code></p>';
        }
        echo '<p><button class="button button-primary hcyb-emergency-enable" data-minutes="60">Włącz na 60 min</button> ';
        echo '<button class="button hcyb-emergency-enable" data-minutes="180">Włącz na 180 min</button> ';
        echo '<button class="button hcyb-emergency-disable">Wyłącz</button></p>';
        echo '<p class="hcyb-muted">Tryb kryzysowy wymusza WAF=BLOCK + wyższy poziom + ostrzejsze limity.</p>';
        echo '</div>';

        echo '<div class="hcyb-card"><h2>Ostatnie zdarzenia</h2>';
        self::render_events_table(10);
        echo '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=hcyb-events')) . '">Pełny dziennik zdarzeń</a></p>';
        echo '</div>';
        echo '</div>'; // grid
        echo '</div>'; // wrap
    }

    public static function page_policies(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $profiles = $cfg['profiles'] ?? [];

        echo '<div class="wrap hcyb"><h1>Polityki</h1>';
        echo '<div class="hcyb-card">';
        echo '<p class="hcyb-muted">Polityki to zestawy ustawień. Możesz je eksportować/importować jako JSON (bez używania wp_options).</p>';
        echo '<table class="widefat striped"><thead><tr><th>Nazwa</th><th>Id</th><th>Akcja</th></tr></thead><tbody>';
        foreach ($profiles as $id => $p) {
            echo '<tr>';
            echo '<td><strong>' . esc_html($p['name'] ?? $id) . '</strong>' . ($id === $active ? ' <span class="hcyb-badge">AKTYWNY</span>' : '') . '</td>';
            echo '<td><code>' . esc_html($id) . '</code></td>';
            echo '<td><button class="button hcyb-set-profile" data-profile="' . esc_attr($id) . '">Ustaw aktywną</button></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';

        echo '<hr>';
        echo '<h2>Eksport / Import</h2>';
        echo '<p class="hcyb-muted">Eksport konfiguracji pełnej (techniczny) oraz eksport polityki podpisany (zalecany).</p>';
        echo '<p><button class="button button-primary hcyb-export">Eksportuj konfigurację (JSON)</button> ';
        echo '<button class="button hcyb-policy-export-signed">Eksportuj aktywną politykę (PODPISANA)</button></p>';
        echo '<textarea id="hcyb-import-json" class="large-text code" rows="10" placeholder="Wklej JSON z eksportu..."></textarea>';
        echo '<p><button class="button hcyb-import">Importuj (nadpisze konfigurację)</button></p>';

        echo '<h3>Import podpisanej polityki</h3>';
        echo '<textarea id="hcyb-import-signed-json" class="large-text code" rows="8" placeholder="Wklej JSON payload... (podpisany eksport)"></textarea>';
        echo '<input type="text" id="hcyb-import-signed-sig" class="regular-text code" placeholder="Podpis (sig)" />';
        echo '<p><button class="button hcyb-policy-import-signed">Importuj podpisaną politykę</button></p>';

        echo '<hr><h2>Wersje polityki (rollback)</h2>';
        echo '<p class="hcyb-muted">Każdy zapis ustawień tworzy snapshot. Możesz cofnąć się jednym kliknięciem.</p>';
        echo '<p><button class="button hcyb-policy-refresh">Odśwież listę</button></p>';
        echo '<div id="hcyb-policy-versions"></div>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '</div></div>';
    }

    public static function page_waf(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $waf = $p['waf'] ?? [];
        $allow = $p['allow'] ?? [];

        echo '<div class="wrap hcyb"><h1>Firewall (WAF)</h1>';
        echo '<div class="hcyb-card">';
        echo '<p class="hcyb-muted">WAF działa w PHP. Domyślnie jest w trybie monitoringu i nie blokuje multimediów (uploads).</p>';

        $rl = (array)($waf['rate_limits'] ?? []);
        $ip_allow = implode("\n", (array)($waf['ip_allow'] ?? []));
        $ip_deny  = implode("\n", (array)($waf['ip_deny'] ?? []));

        echo '<table class="form-table"><tbody>';
        self::row_toggle('Włącz WAF', 'waf_enabled', !empty($waf['enabled']));
        self::row_select('Tryb', 'waf_mode', ['monitor'=>'Monitoruj (loguj)', 'simulate'=>'Symuluj (co by było zablokowane)', 'block'=>'Blokuj (403/429)'], $waf['mode'] ?? 'monitor');
        self::row_select('Poziom blokowania', 'waf_level', ['low'=>'Niski', 'med'=>'Średni', 'high'=>'Wysoki'], $waf['block_level'] ?? 'low');
        self::row_toggle('Fingerprint (IP+User-Agent) dla limitów', 'waf_fingerprint', !empty($waf['fingerprint']));
        self::row_toggle('Zawsze przepuszczaj multimedia (uploads, GET/HEAD)', 'allow_uploads', !empty($allow['uploads_allow']));
        $paths = implode("\n", (array)($allow['paths_allow'] ?? []));
        echo '<tr><th scope="row">Allowlista ścieżek</th><td>';
        echo '<textarea id="hcyb_paths_allow" class="large-text code" rows="6">' . esc_textarea($paths) . '</textarea>';
        echo '<p class="description">Jedna ścieżka na linię. Przykład: /wp-admin/async-upload.php</p>';
        echo '</td></tr>';
        echo '</tbody></table>';

        echo '<hr><h2>Limitowanie żądań (per endpoint)</h2>';
        echo '<p class="hcyb-muted">Limity działają niezależnie od WordPress (własny KV). W trybie Symuluj nie blokujemy, tylko logujemy <code>would_block</code>.</p>';
        echo '<table class="widefat striped hcyb-rl"><thead><tr>';
        echo '<th>Endpoint</th><th>Włącz</th><th>Max</th><th>Okno (s)</th><th>Lock (s)</th><th>Metody</th>';
        echo '</tr></thead><tbody>';
        self::rl_row('wp_login', 'wp-login.php', $rl['wp_login'] ?? []);
        self::rl_row('xmlrpc', 'xmlrpc.php', $rl['xmlrpc'] ?? []);
        self::rl_row('rest', 'REST (/wp-json/...)', $rl['rest'] ?? []);
        self::rl_row('admin_ajax', 'admin-ajax.php', $rl['admin_ajax'] ?? []);
        echo '</tbody></table>';

        echo '<hr><h2>IP allow / deny</h2>';
        echo '<table class="form-table"><tbody>';
        echo '<tr><th scope="row">Allowlista IP</th><td>';
        echo '<textarea id="hcyb_ip_allow" class="large-text code" rows="4" placeholder="np. 1.2.3.4\n5.6.7.8">' . esc_textarea($ip_allow) . '</textarea>';
        echo '<p class="description">IP na allowliście omija WAF i limity.</p>';
        echo '</td></tr>';
        echo '<tr><th scope="row">Denylista IP</th><td>';
        echo '<textarea id="hcyb_ip_deny" class="large-text code" rows="4" placeholder="np. 9.9.9.9">' . esc_textarea($ip_deny) . '</textarea>';
        echo '<p class="description">IP na denyliście jest blokowane w trybie <strong>Blokuj</strong>, a w monitoringu/symulacji tylko logowane.</p>';
        echo '</td></tr>';
        echo '</tbody></table>';

        echo '<p><button class="button button-primary hcyb-save">Zapisz</button></p>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '</div></div>';
    }

    private static function rl_row(string $key, string $label, array $v): void {
        $en = !empty($v['enabled']);
        $max = (int)($v['max'] ?? 60);
        $win = (int)($v['window_sec'] ?? 60);
        $lock = (int)($v['block_sec'] ?? 300);
        $methods = implode(',', (array)($v['only_methods'] ?? []));
        echo '<tr>';
        echo '<td><strong>' . esc_html($label) . '</strong><br><code>' . esc_html($key) . '</code></td>';
        echo '<td><input type="checkbox" id="hcyb_rl_' . esc_attr($key) . '_enabled" ' . checked($en, true, false) . '></td>';
        echo '<td><input type="number" min="1" max="5000" id="hcyb_rl_' . esc_attr($key) . '_max" value="' . esc_attr($max) . '" class="small-text"></td>';
        echo '<td><input type="number" min="5" max="86400" id="hcyb_rl_' . esc_attr($key) . '_window" value="' . esc_attr($win) . '" class="small-text"></td>';
        echo '<td><input type="number" min="5" max="86400" id="hcyb_rl_' . esc_attr($key) . '_lock" value="' . esc_attr($lock) . '" class="small-text"></td>';
        echo '<td><input type="text" id="hcyb_rl_' . esc_attr($key) . '_methods" value="' . esc_attr($methods) . '" placeholder="np. POST" class="regular-text">';
        echo '<p class="description">Puste = wszystkie. Wpisz CSV np. <code>POST,GET</code>.</p></td>';
        echo '</tr>';
    }

    public static function page_hardening(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $hard = $p['hardening'] ?? [];
        $headers = $p['headers'] ?? [];

        echo '<div class="wrap hcyb"><h1>Twardnienie WordPress</h1>';
        echo '<div class="hcyb-grid">';
        echo '<div class="hcyb-card"><h2>Hardening</h2><table class="form-table"><tbody>';
        self::row_select('XML-RPC', 'xmlrpc', ['restrict'=>'Ogranicz (bez pingback)', 'off'=>'Wyłącz', 'on'=>'Włącz'], $hard['xmlrpc'] ?? 'restrict');
        self::row_toggle('Chroń REST /users', 'rest_users', !empty($hard['rest_users']));
        self::row_toggle('Blokuj enumerację autorów (?author=)', 'author_enum', !empty($hard['author_enum']));
        self::row_toggle('Wyłącz edycję plików w panelu', 'file_edit', !empty($hard['file_edit']));
        echo '</tbody></table><p><button class="button button-primary hcyb-save">Zapisz</button></p></div>';

        echo '<div class="hcyb-card"><h2>Nagłówki</h2><table class="form-table"><tbody>';
        self::row_toggle('Włącz nagłówki bezpieczeństwa', 'headers_enabled', !empty($headers['enabled']));
        self::row_toggle('HSTS (tylko jeśli SSL pewny)', 'headers_hsts', !empty($headers['hsts']));
        self::row_select('CSP', 'headers_csp', ['off'=>'Wyłącz', 'report'=>'Report-Only (zalecane)', 'enforce'=>'Wymuszaj'], $headers['csp_mode'] ?? 'report');
        echo '</tbody></table><p class="hcyb-muted">Najpierw CSP w trybie report-only, dopiero potem enforce.</p></div>';
        echo '</div></div>';
    }

    public static function page_scanner(): void {
        echo '<div class="wrap hcyb"><h1>Skaner integralności</h1>';
        echo '<div class="hcyb-card">';
        echo '<p class="hcyb-muted">Skaner nie używa tabel WordPress. Baseline i wyniki trzymamy we własnych tabelach.</p>';
        echo '<p><button class="button hcyb-baseline">Utwórz baseline (plugins/themes)</button> ';
        echo '<button class="button button-primary hcyb-scan-quick">Skan szybki</button> ';
        echo '<button class="button hcyb-fullscan-start">Pełny skan (batch)</button> ';
        echo '<button class="button hcyb-fullscan-stop">Zatrzymaj</button></p>';
        echo '<div class="hcyb-progress" id="hcyb-fullscan-progress" style="display:none"><div class="hcyb-progress__bar" style="width:0%"></div></div>';
        echo '<p class="hcyb-muted">Pełny skan działa w batchach i może wykonywać się w tle (pseudo-cron) bez WP-Cron. Nie blokuje multimediów.</p>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '<h2>Ostatnie zdarzenia skanera</h2>';
        self::render_events_table(15, 'scanner');
        echo '</div></div>';
    }

    
    public static function page_surface(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $hosts = (array)($p['allow']['hosts'] ?? []);
        $home_host = parse_url(home_url('/'), PHP_URL_HOST);
        if ($home_host && !in_array($home_host, $hosts, true)) { array_unshift($hosts, $home_host); }

        echo '<div class="wrap hcyb"><h1>Ekspozycja (Surface Scanner)</h1>';
        echo '<div class="hcyb-card">';
        echo '<p class="hcyb-muted">Skan bez atakowania: sprawdzamy, czy z zewnątrz są dostępne znane wrażliwe ścieżki (np. install.php, .env, .git, backupy) oraz podstawowe nagłówki. Wynik zapisujemy w logach.</p>';
        echo '<p><button class="button button-primary hcyb-surface-scan">Uruchom skan ekspozycji</button></p>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '<div id="hcyb-surface-results"></div>';
        echo '</div></div>';
    }

    /**
     * Reputacja IP: panel użytkowy + szybkie sprawdzenie IP.
     */
    public static function page_reputation(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $rep = $p['ip_reputation'] ?? [];
        $enabled = !empty($rep['enabled']);
        $threshold = (int)($rep['block_threshold'] ?? 80);
        if ($threshold < 0) $threshold = 0;
        if ($threshold > 100) $threshold = 100;

        echo '<div class="wrap hcyb"><h1>Reputacja IP</h1>';
        echo '<div class="hcyb-grid">';

        echo '<div class="hcyb-card">';
        echo '<h2>Ustawienia profilu</h2>';
        echo '<p class="hcyb-muted">Reputacja IP może wspierać decyzje WAF (np. blokuj, gdy wynik ryzyka przekroczy próg). Domyślny provider w tym MVP to heurystyka lokalna (bez zewnętrznych API).</p>';
        echo '<table class="form-table"><tbody>';
        echo '<tr><th scope="row">Włącz reputację IP</th><td><label><input type="checkbox" id="hcyb_rep_enabled" ' . checked($enabled, true, false) . '> <span class="hcyb-muted">ON/OFF</span></label></td></tr>';
        echo '<tr><th scope="row">Próg blokady (0–100)</th><td><input type="number" id="hcyb_rep_threshold" min="0" max="100" value="' . esc_attr($threshold) . '"> <span class="hcyb-muted">Jeśli risk_score ≥ próg, WAF może zablokować (w trybie Blokuj).</span></td></tr>';
        echo '</tbody></table>';
        echo '<p><button class="button button-primary" onclick="window.HCYB.saveReputationSettings();return false;">Zapisz</button></p>';
        echo '<div class="hcyb-status" id="hcyb_ip_status"></div>';
        echo '</div>';

        echo '<div class="hcyb-card">';
        echo '<h2>Szybkie sprawdzenie IP</h2>';
        echo '<p class="hcyb-muted">To narzędzie zapisuje wynik do cache i logów zdarzeń. Nie wymaga zewnętrznych API (heurystyka lokalna).</p>';
        echo '<p><input type="text" id="hcyb_ip_input" class="regular-text" placeholder="np. 8.8.8.8"> <button class="button" onclick="window.HCYB.checkIP();return false;">Sprawdź</button></p>';
        echo '<pre id="hcyb_ip_result" class="hcyb-pre" style="display:none"></pre>';
        echo '</div>';

        echo '</div></div>';
    }

    public static function ajax_surface_scan(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $hosts = (array)($p['allow']['hosts'] ?? []);
        $home_host = parse_url(home_url('/'), PHP_URL_HOST);
        if ($home_host && !in_array($home_host, $hosts, true)) { array_unshift($hosts, $home_host); }
        $out = HCYB_Surface::scan($hosts);
        wp_send_json_success(['message' => 'Skan zakończony.', 'data' => $out]);
    }

    public static function ajax_check_ip(): void {
        self::require_admin();
        $ip = trim((string)($_POST['ip'] ?? ''));
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => 'Niepoprawny adres IP.'], 400);
        }
        $rec = HCYB_Reputation::get_or_fetch($ip, 'local_heuristic');
        HCYB_Logger::event('low', 'reputation', 'checked', ['message' => 'Sprawdzono IP', 'meta' => ['ip' => $ip, 'record' => $rec]]);
        wp_send_json_success(['record' => $rec]);
    }

    public static function ajax_save_reputation(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        if (!isset($cfg['profiles'][$active])) wp_send_json_error(['message' => 'Brak profilu aktywnego.'], 400);

        $p = $cfg['profiles'][$active];
        $en = !empty($_POST['enabled']);
        $thr = (int)($_POST['block_threshold'] ?? 80);
        if ($thr < 0) $thr = 0;
        if ($thr > 100) $thr = 100;

        if (!isset($p['ip_reputation']) || !is_array($p['ip_reputation'])) $p['ip_reputation'] = [];
        $p['ip_reputation']['enabled'] = $en;
        $p['ip_reputation']['block_threshold'] = $thr;
        if (empty($p['ip_reputation']['provider'])) $p['ip_reputation']['provider'] = 'local_heuristic';
        if (empty($p['ip_reputation']['ttl_days'])) $p['ip_reputation']['ttl_days'] = 14;

        $cfg['profiles'][$active] = $p;
        if (!self::save_cfg($cfg)) wp_send_json_error(['message' => 'Nie udało się zapisać konfiguracji.'], 500);

        HCYB_Logger::event('low', 'admin', 'reputation_saved', ['message' => 'Zapisano ustawienia reputacji IP', 'meta' => ['enabled' => $en, 'threshold' => $thr]]);
        wp_send_json_success(['message' => 'Zapisano.']);
    }

public static function page_events(): void {
        echo '<div class="wrap hcyb"><h1>Zdarzenia</h1>';
        echo '<div class="hcyb-card">';
        self::render_events_table(50);
        echo '</div></div>';
    }

    public static function page_settings(): void {
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $hosts = implode("\n", (array)($p['allow']['hosts'] ?? []));
        $iprep = $p['ip_reputation'] ?? ['enabled'=>false,'provider'=>'local_heuristic','ttl_days'=>14,'block_threshold'=>80];
        $adapt = $p['adaptive'] ?? ['enabled'=>false,'window_min'=>5,'threshold'=>60,'duration_min'=>60];

        echo '<div class="wrap hcyb"><h1>Ustawienia</h1>';
        echo '<div class="hcyb-grid">';
        echo '<div class="hcyb-card"><h2>Hosty / subdomeny</h2>';
        echo '<p class="hcyb-muted">Jeśli obsługujesz subdomeny w ramach tej instalacji, wpisz je tutaj (jedna linia). Służy do spójnych polityk (np. HSTS/CSP) i raportów.</p>';
        echo '<textarea id="hcyb_hosts" class="large-text code" rows="6">' . esc_textarea($hosts) . '</textarea>';
        echo '<p><button class="button button-primary hcyb-save">Zapisz</button></p>';
        echo '</div>';

        echo '<div class="hcyb-card"><h2>Reputacja IP (opcjonalnie)</h2>';
        self::row_toggle('Włącz sprawdzanie IP (zewnętrzne API)', 'iprep_enabled', !empty($iprep['enabled']));
        self::row_select('Provider', 'iprep_provider', ['local_heuristic'=>'Lokalna heurystyka (bez API)', 'ipapi'=>'ipapi.co (proste)', 'ipinfo'=>'ipinfo.io (token)'], $iprep['provider'] ?? 'local_heuristic');
        echo '<tr><th scope="row">TTL cache (dni)</th><td><input id="hcyb_iprep_ttl" type="number" min="1" max="90" value="' . esc_attr((int)($iprep['ttl_days'] ?? 14)) . '"></td></tr>';
        echo '<tr><th scope="row">Próg blokady (0–100)</th><td><input id="hcyb_iprep_block_threshold" type="number" min="0" max="100" value="' . esc_attr((int)($iprep['block_threshold'] ?? 80)) . '"></td></tr>';
        echo '<tr><td colspan="2"><p class="description">Uwaga: opcja wymaga dostępu serwera do internetu. Wyniki są cache’owane we własnej tabeli.</p></td></tr>';
        echo '<p><button class="button button-primary hcyb-save">Zapisz</button></p>';
        echo '</div>';

        echo '<div class="hcyb-card"><h2>Reakcje adaptacyjne</h2>';
        echo '<p class="hcyb-muted">Automatyczne włączanie trybu kryzysowego, gdy w krótkim oknie czasowym pojawi się dużo blokad/wykryć.</p>';
        echo '<table class="form-table"><tbody>';
        self::row_toggle('Włącz adaptacyjne reakcje', 'adaptive_enabled', !empty($adapt['enabled']));
        echo '<tr><th scope="row">Okno (min)</th><td><input id="hcyb_adaptive_window" type="number" min="1" max="60" value="' . esc_attr((int)($adapt['window_min'] ?? 5)) . '"></td></tr>';
        echo '<tr><th scope="row">Próg zdarzeń</th><td><input id="hcyb_adaptive_threshold" type="number" min="10" max="5000" value="' . esc_attr((int)($adapt['threshold'] ?? 60)) . '"></td></tr>';
        echo '<tr><th scope="row">Czas trybu kryzysowego (min)</th><td><input id="hcyb_adaptive_duration" type="number" min="5" max="1440" value="' . esc_attr((int)($adapt['duration_min'] ?? 60)) . '"></td></tr>';
        echo '</tbody></table>';
        echo '<p><button class="button button-primary hcyb-save">Zapisz</button></p>';
        echo '<p class="hcyb-muted">Wskaźnik: zdarzenia WAF (blocked/detected/would_block) + login (lockout/blocked).</p>';
        echo '</div>';

        echo '<div class="hcyb-card"><h2>MU-loader (WAF przed WordPress)</h2>';
        echo '<p class="hcyb-muted">Opcjonalnie możemy wygenerować mały loader do <code>wp-content/mu-plugins</code>, żeby WAF odpalał zanim WP załaduje wtyczki. Jeśli katalog jest zapisywalny, kliknij poniżej.</p>';
        echo '<p><button class="button hcyb-generate-mu">Wygeneruj MU-loader</button></p>';
        echo '<div class="hcyb-status" id="hcyb-status"></div>';
        echo '</div>';

        echo '</div></div>';
    }

    private static function row_toggle(string $label, string $id, bool $val): void {
        echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
        echo '<label><input type="checkbox" id="hcyb_' . esc_attr($id) . '" ' . checked($val, true, false) . '> <span class="hcyb-muted">ON/OFF</span></label>';
        echo '</td></tr>';
    }

    private static function row_select(string $label, string $id, array $opts, string $val): void {
        echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
        echo '<select id="hcyb_' . esc_attr($id) . '">';
        foreach ($opts as $k=>$t) {
            echo '<option value="' . esc_attr($k) . '" ' . selected($val, $k, false) . '>' . esc_html($t) . '</option>';
        }
        echo '</select></td></tr>';
    }

    private static function render_events_table(int $limit = 50, ?string $category_filter = null): void {
        global $wpdb;
        [$t_events,] = HCYB_DB::tables()['events'];

        $sql = "SELECT id, created_at, level, category, action, ip, method, path, rule_id, message FROM $t_events";
        if ($category_filter) {
            $sql .= $wpdb->prepare(" WHERE category=%s", $category_filter);
        }
        $sql .= " ORDER BY id DESC LIMIT " . (int)$limit;
        $rows = $wpdb->get_results($sql);

        echo '<table class="widefat striped"><thead><tr>';
        echo '<th>Czas (UTC)</th><th>Poziom</th><th>Kategoria</th><th>Akcja</th><th>IP</th><th>Żądanie</th><th>Reguła</th><th>Opis</th>';
        echo '</tr></thead><tbody>';
        if (!$rows) {
            echo '<tr><td colspan="8" class="hcyb-muted">Brak zdarzeń.</td></tr>';
        } else {
            foreach ($rows as $r) {
                $req = trim((string)$r->method) . ' ' . (string)$r->path;
                echo '<tr>';
                echo '<td>' . esc_html((string)$r->created_at) . '</td>';
                echo '<td><span class="hcyb-level hcyb-level-' . esc_attr((string)$r->level) . '">' . esc_html((string)$r->level) . '</span></td>';
                echo '<td>' . esc_html((string)$r->category) . '</td>';
                echo '<td>' . esc_html((string)$r->action) . '</td>';
                echo '<td><code>' . esc_html((string)$r->ip) . '</code></td>';
                echo '<td class="hcyb-req"><code>' . esc_html($req) . '</code></td>';
                echo '<td><code>' . esc_html((string)$r->rule_id) . '</code></td>';
                echo '<td>' . esc_html((string)$r->message) . '</td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table>';
    }

    private static function require_admin(): void {
        if (!current_user_can('manage_options')) wp_send_json_error(['message'=>'Brak uprawnień.'], 403);
        check_ajax_referer('hcyb_nonce', 'nonce');
    }

    public static function ajax_save_settings(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        $active = $cfg['profile_active'] ?? 'domyslny';
        if (!isset($cfg['profiles'][$active])) wp_send_json_error(['message'=>'Brak profilu aktywnego.'], 400);

        $p = $cfg['profiles'][$active];

        // WAF
        $p['waf']['enabled'] = !empty($_POST['waf_enabled']);
        $p['waf']['mode'] = sanitize_text_field((string)($_POST['waf_mode'] ?? ($p['waf']['mode'] ?? 'monitor')));
        $p['waf']['block_level'] = sanitize_text_field((string)($_POST['waf_level'] ?? ($p['waf']['block_level'] ?? 'low')));
        $p['waf']['fingerprint'] = !empty($_POST['waf_fingerprint']);

        // Rate limits
        $rl_keys = ['wp_login','xmlrpc','rest','admin_ajax'];
        foreach ($rl_keys as $k) {
            $en = !empty($_POST['rl_' . $k . '_enabled']);
            $max = (int)($_POST['rl_' . $k . '_max'] ?? 0);
            $win = (int)($_POST['rl_' . $k . '_window'] ?? 0);
            $lock = (int)($_POST['rl_' . $k . '_lock'] ?? 0);
            $methods_raw = (string)($_POST['rl_' . $k . '_methods'] ?? '');
            $methods = array_values(array_filter(array_map('trim', preg_split('/\s*,\s*/', strtoupper($methods_raw)))));
            $p['waf']['rate_limits'][$k] = [
                'enabled' => $en,
                'max' => $max > 0 ? $max : (int)($p['waf']['rate_limits'][$k]['max'] ?? 60),
                'window_sec' => $win > 0 ? $win : (int)($p['waf']['rate_limits'][$k]['window_sec'] ?? 60),
                'block_sec' => $lock > 0 ? $lock : (int)($p['waf']['rate_limits'][$k]['block_sec'] ?? 300),
                'only_methods' => $methods,
            ];
        }

        // IP allow/deny
        $ip_allow_raw = (string)($_POST['ip_allow'] ?? '');
        $ip_deny_raw = (string)($_POST['ip_deny'] ?? '');
        $ip_allow = array_values(array_filter(array_map('trim', preg_split("/\r\n|\r|\n/", $ip_allow_raw))));
        $ip_deny = array_values(array_filter(array_map('trim', preg_split("/\r\n|\r|\n/", $ip_deny_raw))));
        $p['waf']['ip_allow'] = $ip_allow;
        $p['waf']['ip_deny'] = $ip_deny;

        $p['allow']['uploads_allow'] = !empty($_POST['allow_uploads']);
        $paths_raw = (string)($_POST['paths_allow'] ?? '');
        $paths = array_values(array_filter(array_map('trim', preg_split("/\r\n|\r|\n/", $paths_raw))));
        if (!empty($paths)) $p['allow']['paths_allow'] = $paths;

        // Hardening
        $p['hardening']['xmlrpc'] = sanitize_text_field((string)($_POST['xmlrpc'] ?? ($p['hardening']['xmlrpc'] ?? 'restrict')));
        $p['hardening']['rest_users'] = !empty($_POST['rest_users']);
        $p['hardening']['author_enum'] = !empty($_POST['author_enum']);
        $p['hardening']['file_edit'] = !empty($_POST['file_edit']);

        // Headers
        $p['headers']['enabled'] = !empty($_POST['headers_enabled']);
        $p['headers']['hsts'] = !empty($_POST['headers_hsts']);
        $p['headers']['csp_mode'] = sanitize_text_field((string)($_POST['headers_csp'] ?? ($p['headers']['csp_mode'] ?? 'report')));

        // Hosts
        if (isset($_POST['hosts'])) {
            $hosts_raw = (string)$_POST['hosts'];
            $hosts = array_values(array_filter(array_map('trim', preg_split("/\r\n|\r|\n/", $hosts_raw))));
            $p['allow']['hosts'] = $hosts;
        }

        // IP rep
        $p['ip_reputation']['enabled'] = !empty($_POST['iprep_enabled']);
        $p['ip_reputation']['provider'] = sanitize_text_field((string)($_POST['iprep_provider'] ?? ($p['ip_reputation']['provider'] ?? 'ipapi')));
        $ttl = (int)($_POST['iprep_ttl'] ?? ($p['ip_reputation']['ttl_days'] ?? 14));
        if ($ttl < 1) $ttl = 1;
        if ($ttl > 90) $ttl = 90;
        $p['ip_reputation']['ttl_days'] = $ttl;

        $thr = (int)($_POST['iprep_block_threshold'] ?? ($p['ip_reputation']['block_threshold'] ?? 80));
        if ($thr < 0) $thr = 0;
        if ($thr > 100) $thr = 100;
        $p['ip_reputation']['block_threshold'] = $thr;

        // Reakcje adaptacyjne (auto-tryb kryzysowy)
        $p['adaptive']['enabled'] = !empty($_POST['adaptive_enabled']);
        $aw = (int)($_POST['adaptive_window'] ?? ($p['adaptive']['window_min'] ?? 5));
        $at = (int)($_POST['adaptive_threshold'] ?? ($p['adaptive']['threshold'] ?? 60));
        $ad = (int)($_POST['adaptive_duration'] ?? ($p['adaptive']['duration_min'] ?? 60));
        if ($aw < 1) $aw = 1; if ($aw > 60) $aw = 60;
        if ($at < 10) $at = 10; if ($at > 5000) $at = 5000;
        if ($ad < 5) $ad = 5; if ($ad > 1440) $ad = 1440;
        $p['adaptive']['window_min'] = $aw;
        $p['adaptive']['threshold'] = $at;
        $p['adaptive']['duration_min'] = $ad;

        $cfg['profiles'][$active] = $p;

        if (!self::save_cfg($cfg)) wp_send_json_error(['message'=>'Nie udało się zapisać konfiguracji.'], 500);

        // snapshot polityki (rollback)
        HCYB_Policies::create_snapshot('settings_saved', get_current_user_id(), 'ui');

        HCYB_Logger::event('low', 'admin', 'settings_saved', ['message' => 'Zapisano ustawienia profilu: ' . $active]);
        wp_send_json_success(['message'=>'Zapisano.']);
    }

    public static function ajax_export(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        wp_send_json_success(['config'=>$cfg]);
    }

    public static function ajax_import(): void {
        self::require_admin();
        $json = (string)($_POST['json'] ?? '');
        $data = json_decode($json, true);
        if (!is_array($data) || empty($data['profiles'])) {
            wp_send_json_error(['message'=>'Niepoprawny JSON.'], 400);
        }
        if (!self::save_cfg($data)) wp_send_json_error(['message'=>'Nie udało się zapisać konfiguracji.'], 500);
        HCYB_Policies::create_snapshot('config_imported', get_current_user_id(), 'import');
        HCYB_Logger::event('med', 'admin', 'config_imported', ['message'=>'Zaimportowano konfigurację.']);
        wp_send_json_success(['message'=>'Zaimportowano konfigurację.']);
    }

    public static function ajax_policy_export_signed(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        $active = (string)($cfg['profile_active'] ?? 'domyslny');
        $out = HCYB_Policies::export_signed($active);
        wp_send_json_success($out);
    }

    public static function ajax_policy_import_signed(): void {
        self::require_admin();
        $json = (string)($_POST['json'] ?? '');
        $sig = (string)($_POST['sig'] ?? '');
        if ($json === '' || $sig === '') wp_send_json_error(['message'=>'Brak danych do importu.'], 400);
        $ok = HCYB_Policies::import_signed($json, $sig, get_current_user_id());
        if (!$ok) wp_send_json_error(['message'=>'Podpis nieprawidłowy lub zły format.'], 400);
        wp_send_json_success(['message'=>'Zaimportowano podpisaną politykę.']);
    }

    public static function ajax_policy_list_versions(): void {
        self::require_admin();
        $cfg = self::get_cfg();
        $active = (string)($cfg['profile_active'] ?? 'domyslny');
        $rows = HCYB_Policies::list_snapshots($active, 30);
        wp_send_json_success(['active' => $active, 'versions' => $rows]);
    }

    public static function ajax_policy_diff(): void {
        self::require_admin();
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0) wp_send_json_error(['message'=>'Brak id.'], 400);
        $snap = HCYB_Policies::get_snapshot($id);
        if (!$snap) wp_send_json_error(['message'=>'Nie znaleziono wersji.'], 404);
        $payload = $snap['payload'] ?? [];
        $snap_profile = (array)($payload['profile'] ?? []);

        $cfg = self::get_cfg();
        $active = (string)($cfg['profile_active'] ?? 'domyslny');
        $curr_profile = (array)($cfg['profiles'][$active] ?? []);
        $changes = HCYB_Policies::diff_profile($snap_profile, $curr_profile);
        wp_send_json_success(['count' => count($changes), 'changes' => array_slice($changes, 0, 200)]);
    }

    public static function ajax_policy_rollback(): void {
        self::require_admin();
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0) wp_send_json_error(['message'=>'Brak id.'], 400);
        $ok = HCYB_Policies::rollback_to($id, get_current_user_id());
        if (!$ok) wp_send_json_error(['message'=>'Rollback nieudany.'], 500);
        wp_send_json_success(['message'=>'Przywrócono politykę.']);
    }

    public static function ajax_baseline(): void {
        self::require_admin();
        $baseline_id = 'bl_' . wp_generate_password(12, false, false) . '_' . time();
        $count = HCYB_Scanner::create_baseline($baseline_id);
        HCYB_Logger::event('low','scanner','baseline_created',['message'=>"Utworzono baseline: $baseline_id", 'meta'=>['count'=>$count]]);
        wp_send_json_success(['message'=>"Baseline utworzony ($count plików).", 'baseline_id'=>$baseline_id]);
    }

    public static function ajax_scan_quick(): void {
        self::require_admin();
        $res = HCYB_Scanner::scan_quick();
        HCYB_Logger::event('med','scanner','scan_quick',['message'=>'Skan szybki zakończony', 'meta'=>$res]);
        wp_send_json_success(['message'=>"Skan OK. Zmiany: {$res['changed']}, nowe: {$res['new']}, podejrzane: {$res['suspicious']}.", 'result'=>$res]);
    }



    public static function ajax_fullscan_start(): void {
        self::require_admin();
        $limit = (int)($_POST['limit'] ?? 250);
        if ($limit < 50) $limit = 50;
        if ($limit > 2000) $limit = 2000;
        $res = HCYB_Scanner::fullscan_start($limit);
        if (empty($res['ok'])) {
            wp_send_json_error(['message' => $res['message'] ?? 'Nie udało się uruchomić skanu.'], 400);
        }
        wp_send_json_success(['message' => 'Uruchomiono pełny skan (batch).', 'status' => $res]);
    }

    public static function ajax_fullscan_tick(): void {
        self::require_admin();
        $limit = isset($_POST['limit']) ? (int)$_POST['limit'] : null;
        $res = HCYB_Scanner::fullscan_tick($limit);
        wp_send_json_success(['result' => $res]);
    }

    public static function ajax_fullscan_status(): void {
        self::require_admin();
        $st = HCYB_Scanner::fullscan_status();
        wp_send_json_success(['status' => $st]);
    }

    public static function ajax_fullscan_stop(): void {
        self::require_admin();
        HCYB_Scanner::fullscan_stop();
        wp_send_json_success(['message' => 'Zatrzymano.']);
    }
    public static function ajax_generate_mu_loader(): void {
        self::require_admin();
        $ok = HCYB_MU_Loader::generate();
        if (!$ok['ok']) wp_send_json_error(['message'=>$ok['message']], 500);
        HCYB_Logger::event('low','admin','mu_loader_generated',['message'=>$ok['message']]);
        wp_send_json_success(['message'=>$ok['message']]);
    }

    public static function ajax_emergency_enable(): void {
        self::require_admin();
        check_ajax_referer('hcyb_nonce', 'nonce');
        $minutes = isset($_POST['minutes']) ? (int)$_POST['minutes'] : 60;
        if ($minutes < 5) $minutes = 5;
        if ($minutes > 1440) $minutes = 1440;
        $until = class_exists('HCYB_Emergency') ? HCYB_Emergency::enable($minutes, 'admin') : 0;
        wp_send_json_success(['until'=>$until]);
    }

    public static function ajax_emergency_disable(): void {
        self::require_admin();
        check_ajax_referer('hcyb_nonce', 'nonce');
        if (class_exists('HCYB_Emergency')) {
            HCYB_Emergency::disable('admin');
        }
        wp_send_json_success(['ok'=>true]);
    }
}

// Scanner + MU-loader w oddzielnych plikach
require_once HCYB_PATH . 'includes/class-hcyb-scanner.php';
require_once HCYB_PATH . 'includes/class-hcyb-mu-loader.php';
