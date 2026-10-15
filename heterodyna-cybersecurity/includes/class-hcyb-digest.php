<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Digest {
    public static function init(): void {
        add_action('shutdown', [__CLASS__, 'tick'], 2);
    }

    public static function tick(): void {
        $last_tick = (int)HCYB_DB::kv_get('hcyb_digest_tick', 0);
        if (time() - $last_tick < 3600) return;
        HCYB_DB::kv_set('hcyb_digest_tick', time(), 7200);

        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $d = $p['digest'] ?? [];
        if (empty($d['enabled'])) return;

        $emails_raw = (string)($d['emails'] ?? '');
        $emails = array_filter(array_map('trim', preg_split('/[;,\s]+/', $emails_raw) ?: []));
        if (!$emails) return;

        $dow = (int)($d['day_of_week'] ?? 1);
        if ($dow < 1 || $dow > 7) $dow = 1;
        $hour = (int)($d['hour'] ?? 9);
        if ($hour < 0 || $hour > 23) $hour = 9;
        $days = (int)($d['period_days'] ?? 7);
        if ($days < 1 || $days > 30) $days = 7;

        $now_wp = (int)current_time('timestamp');
        $w = (int)gmdate('N', $now_wp);
        $target_ts = strtotime(gmdate('Y-m-d', $now_wp) . sprintf(' %02d:00:00', $hour));
        if (!($w === $dow && $now_wp >= $target_ts)) return;

        $last_sent = (int)HCYB_DB::kv_get('hcyb_digest_last', 0);
        if ($last_sent && (time() - $last_sent) < (5 * 86400)) return;

        $subject = 'HCYB: raport tygodniowy • ' . preg_replace('/^https?:\/\//', '', (string)get_site_url());
        $html = HCYB_Reports::render_html($days);
        $headers = ['Content-Type: text/html; charset=UTF-8'];

        foreach ($emails as $to) {
            if (!is_email($to)) continue;
            @wp_mail($to, $subject, $html, $headers);
        }

        HCYB_DB::kv_set('hcyb_digest_last', time(), 60 * 86400);
        HCYB_Logger::event('low', 'reports', 'weekly_digest_sent', [
            'message' => 'Wysłano raport tygodniowy (' . $days . ' dni) do: ' . implode(', ', $emails),
            'meta' => ['days'=>$days,'to'=>$emails]
        ]);
    }

    public static function send_test_now(int $days = 7): bool {
        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $d = $p['digest'] ?? [];
        $emails_raw = (string)($d['emails'] ?? '');
        $emails = array_filter(array_map('trim', preg_split('/[;,\s]+/', $emails_raw) ?: []));
        if (!$emails) return false;
        $subject = 'HCYB: test raportu • ' . preg_replace('/^https?:\/\//', '', (string)get_site_url());
        $html = HCYB_Reports::render_html($days);
        $headers = ['Content-Type: text/html; charset=UTF-8'];
        $ok = false;
        foreach ($emails as $to) {
            if (!is_email($to)) continue;
            $ok = (bool)wp_mail($to, $subject, $html, $headers) || $ok;
        }
        return $ok;
    }
}
