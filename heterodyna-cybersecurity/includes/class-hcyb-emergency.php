<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Emergency {
    public static function init(): void {
        // nic
    }

    public static function until_ts(): int {
        return (int)HCYB_DB::kv_get('hcyb_emergency_until', 0);
    }

    public static function is_active(): bool {
        $until = self::until_ts();
        return $until && time() < $until;
    }

    public static function enable(int $minutes = 60, string $reason = 'manual'): int {
        if ($minutes < 5) $minutes = 5;
        if ($minutes > 1440) $minutes = 1440;
        $until = time() + ($minutes * 60);
        HCYB_DB::kv_set('hcyb_emergency_until', $until, ($minutes * 60) + 3600);
        HCYB_DB::kv_set('hcyb_emergency_reason', $reason, ($minutes * 60) + 3600);
        HCYB_Logger::event('high', 'emergency', 'enabled', [
            'message' => 'Włączono tryb kryzysowy na ' . $minutes . ' min (' . $reason . ')',
            'meta' => ['minutes'=>$minutes,'reason'=>$reason,'until'=>$until]
        ]);
        return $until;
    }

    public static function disable(string $reason = 'manual'): void {
        HCYB_DB::kv_set('hcyb_emergency_until', 0, 3600);
        HCYB_DB::kv_set('hcyb_emergency_reason', $reason, 3600);
        HCYB_Logger::event('med', 'emergency', 'disabled', [
            'message' => 'Wyłączono tryb kryzysowy (' . $reason . ')',
            'meta' => ['reason'=>$reason]
        ]);
    }

    // Nadpisuje skuteczne parametry ochrony w trybie kryzysowym.
    public static function apply_overrides(array $profile, array &$waf, string &$mode, string &$level): void {
        if (!self::is_active()) return;

        $waf['enabled'] = true;
        $mode = 'block';
        $level = 'high';
        $waf['block_level'] = 'high';

        // dociśnij rate-limity (bezpiecznie: tylko jeśli istnieją)
        if (!empty($waf['rate_limits']) && is_array($waf['rate_limits'])) {
            foreach ($waf['rate_limits'] as $k => $rl) {
                if (!is_array($rl)) continue;
                $rl['enabled'] = true;
                $rl['max'] = max(1, (int)ceil(((int)($rl['max'] ?? 60)) * 0.5));
                $rl['block_sec'] = max((int)($rl['block_sec'] ?? 300), 1800);
                $waf['rate_limits'][$k] = $rl;
            }
        }
    }
}
