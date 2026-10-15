<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Adaptive {
    public static function init(): void {
        add_action('shutdown', [__CLASS__, 'tick'], 3);
    }

    public static function tick(): void {
        // max co 5 minut
        $last = (int)HCYB_DB::kv_get('hcyb_adapt_tick', 0);
        if (time() - $last < 300) return;
        HCYB_DB::kv_set('hcyb_adapt_tick', time(), 900);

        $cfg = HCYB_DB::get_config('hcyb', []);
        $active = $cfg['profile_active'] ?? 'domyslny';
        $p = $cfg['profiles'][$active] ?? [];
        $a = $p['adaptive'] ?? [];
        if (empty($a['enabled'])) return;

        $window_min = (int)($a['window_min'] ?? 5);
        $threshold = (int)($a['threshold'] ?? 60);
        $duration_min = (int)($a['duration_min'] ?? 60);
        if ($window_min < 1) $window_min = 1;
        if ($window_min > 60) $window_min = 60;
        if ($threshold < 10) $threshold = 10;
        if ($duration_min < 5) $duration_min = 5;
        if ($duration_min > 1440) $duration_min = 1440;

        global $wpdb;
        [$t_events,] = HCYB_DB::tables()['events'];
        $cut = gmdate('Y-m-d H:i:s', time() - ($window_min * 60));

        // liczymy tylko zdarzenia WAF i login lock (realne wskaźniki ataku)
        $cnt = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $t_events WHERE created_at >= %s AND ((category='waf' AND action IN ('blocked','detected','would_block')) OR (category='login' AND action IN ('lockout','blocked')))" ,
            $cut
        ));

        if ($cnt >= $threshold) {
            if (!HCYB_Emergency::is_active()) {
                HCYB_Emergency::enable($duration_min, 'adaptive');
                HCYB_Logger::event('high', 'adaptive', 'trigger', [
                    'message' => 'Automatycznie włączono tryb kryzysowy: ' . $cnt . ' zdarzeń / ' . $window_min . ' min',
                    'meta' => ['count'=>$cnt,'window_min'=>$window_min,'threshold'=>$threshold,'duration_min'=>$duration_min]
                ]);
            }
        }
    }
}
