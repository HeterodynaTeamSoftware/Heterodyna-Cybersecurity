<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Scanner {

    private static function iter_files(string $base, array $extensions = ['php']): array {
        $out = [];
        if (!is_dir($base)) return $out;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            /** @var SplFileInfo $file */
            if (!$file->isFile()) continue;
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, $extensions, true)) continue;
            $path = $file->getPathname();
            $out[] = $path;
        }
        return $out;
    }

    public static function create_baseline(string $baseline_id): int {
        global $wpdb;
        [$t_baseline,] = HCYB_DB::tables()['baseline'];

        $roots = [
            'plugins' => WP_PLUGIN_DIR,
            'themes'  => get_theme_root(),
        ];

        $count = 0;
        foreach ($roots as $scope => $root) {
            $files = self::iter_files($root, ['php']);
            foreach ($files as $path) {
                $hash = hash_file('sha256', $path) ?: '';
                $size = @filesize($path);
                $mtime = @filemtime($path);
                $wpdb->insert($t_baseline, [
                    'file_path' => $path,
                    'file_hash' => $hash,
                    'file_size' => is_numeric($size) ? (int)$size : null,
                    'file_mtime' => is_numeric($mtime) ? (int)$mtime : null,
                    'scope' => $scope,
                    'baseline_id' => $baseline_id,
                    'created_at' => gmdate('Y-m-d H:i:s'),
                ], ['%s','%s','%d','%d','%s','%s','%s']);
                $count++;
                if ($count > 20000) break; // bezpiecznik
            }
        }

        HCYB_DB::kv_set('hcyb_last_baseline', $baseline_id, 365*86400);
        return $count;
    }

    public static function scan_quick(): array {
        global $wpdb;
        [$t_baseline,] = HCYB_DB::tables()['baseline'];

        $baseline_id = (string)HCYB_DB::kv_get('hcyb_last_baseline', '');
        if ($baseline_id === '') {
            return ['error' => 'Brak baseline. Najpierw utwórz baseline.', 'changed'=>0,'new'=>0,'suspicious'=>0];
        }

        // wczytaj baseline do mapy (na szybko, limit)
        $rows = $wpdb->get_results($wpdb->prepare("SELECT file_path, file_hash FROM $t_baseline WHERE baseline_id=%s", $baseline_id));
        $map = [];
        foreach ($rows as $r) {
            $map[(string)$r->file_path] = (string)$r->file_hash;
        }

        $changed = 0; $new = 0; $susp = 0;

        $targets = array_merge(
            self::iter_files(WP_PLUGIN_DIR, ['php']),
            self::iter_files(get_theme_root(), ['php'])
        );

        foreach ($targets as $path) {
            $hash = hash_file('sha256', $path) ?: '';
            if (!isset($map[$path])) {
                $new++;
            } elseif ($map[$path] !== $hash) {
                $changed++;
            }

            // prosta heurystyka webshell
            $content = @file_get_contents($path, false, null, 0, 200000); // max 200KB
            if (is_string($content)) {
                if (preg_match('/(base64_decode\s*\(|gzinflate\s*\(|eval\s*\(|assert\s*\(|preg_replace\s*\(\s*\/.+\/e)/i', $content)) {
                    $susp++;
                }
            }
            if (($new + $changed) > 5000) break; // bezpiecznik
        }

        return ['baseline_id'=>$baseline_id,'changed'=>$changed,'new'=>$new,'suspicious'=>$susp,'scanned'=>count($targets)];
    }


    /**
     * Start pełnego skanu integralności na bazie istniejącego baseline.
     * Skan idzie w batchach (tick) i zapisuje progres w KV.
     */
    public static function fullscan_start(int $batch_limit = 250): array {
        $baseline_id = (string)HCYB_DB::kv_get('hcyb_last_baseline', '');
        if ($baseline_id === '') {
            return ['ok'=>false, 'message'=>'Brak baseline. Najpierw utwórz baseline.'];
        }
        global $wpdb;
        [$t_baseline,] = HCYB_DB::tables()['baseline'];
        $total = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $t_baseline WHERE baseline_id=%s", $baseline_id));

        $scan_id = 'full_' . gmdate('Ymd_His') . '_' . wp_generate_password(6, false, false);
        HCYB_DB::kv_set('hcyb_fullscan_active', '1', 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_id', $scan_id, 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_baseline', $baseline_id, 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_offset', '0', 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_total', (string)$total, 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_limit', (string)max(50, min(2000, $batch_limit)), 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_started', gmdate('Y-m-d H:i:s'), 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_last_tick', '0', 7*86400);

        HCYB_Logger::event('low','scanner','fullscan_start',[
            'message'=>'Uruchomiono pełny skan integralności (batch).',
            'meta'=>['scan_id'=>$scan_id,'baseline_id'=>$baseline_id,'total'=>$total]
        ]);

        return ['ok'=>true,'scan_id'=>$scan_id,'baseline_id'=>$baseline_id,'total'=>$total,'offset'=>0];
    }

    public static function fullscan_stop(): void {
        HCYB_DB::kv_set('hcyb_fullscan_active', '0', 7*86400);
        HCYB_Logger::event('low','scanner','fullscan_stop',[
            'message'=>'Zatrzymano pełny skan integralności.',
            'meta'=>['scan_id'=>(string)HCYB_DB::kv_get('hcyb_fullscan_id','')]
        ]);
    }

    public static function fullscan_status(): array {
        $active = (string)HCYB_DB::kv_get('hcyb_fullscan_active','0') === '1';
        $scan_id = (string)HCYB_DB::kv_get('hcyb_fullscan_id','');
        $baseline_id = (string)HCYB_DB::kv_get('hcyb_fullscan_baseline','');
        $offset = (int)HCYB_DB::kv_get('hcyb_fullscan_offset','0');
        $total = (int)HCYB_DB::kv_get('hcyb_fullscan_total','0');
        $started = (string)HCYB_DB::kv_get('hcyb_fullscan_started','');
        return ['active'=>$active,'scan_id'=>$scan_id,'baseline_id'=>$baseline_id,'offset'=>$offset,'total'=>$total,'started'=>$started];
    }

    /**
     * Wykonuje jeden tick pełnego skanu. Zwraca statystyki i aktualny progres.
     */
    public static function fullscan_tick(?int $limit = null): array {
        $st = self::fullscan_status();
        if (!$st['active']) return ['done'=>true,'message'=>'Skan nieaktywny.','status'=>$st];
        $baseline_id = (string)$st['baseline_id'];
        if ($baseline_id === '') return ['done'=>true,'message'=>'Brak baseline_id.','status'=>$st];

        $offset = (int)$st['offset'];
        $total = (int)$st['total'];
        $limit = $limit ?? (int)HCYB_DB::kv_get('hcyb_fullscan_limit','250');
        if ($limit < 50) $limit = 50;
        if ($limit > 2000) $limit = 2000;

        global $wpdb;
        [$t_baseline,] = HCYB_DB::tables()['baseline'];
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT file_path, file_hash FROM $t_baseline WHERE baseline_id=%s ORDER BY id ASC LIMIT %d OFFSET %d",
            $baseline_id,
            $limit,
            $offset
        ));

        $checked = 0; $changed = 0; $missing = 0; $susp = 0;

        foreach ($rows as $r) {
            $path = (string)$r->file_path;
            $base_hash = (string)$r->file_hash;
            $checked++;

            if (!is_file($path)) {
                $missing++;
                continue;
            }
            $hash = hash_file('sha256', $path) ?: '';
            if ($hash !== '' && $base_hash !== '' && $hash !== $base_hash) {
                $changed++;
            }
            // heurystyka (lekka)
            $content = @file_get_contents($path, false, null, 0, 120000);
            if (is_string($content) && preg_match('/(base64_decode\s*\(|gzinflate\s*\(|eval\s*\(|assert\s*\(|preg_replace\s*\(\s*\/.+\/e)/i', $content)) {
                $susp++;
            }
        }

        $new_offset = $offset + $checked;
        HCYB_DB::kv_set('hcyb_fullscan_offset', (string)$new_offset, 7*86400);
        HCYB_DB::kv_set('hcyb_fullscan_last_tick', (string)time(), 7*86400);

        $done = ($new_offset >= $total) or ($checked == 0);
        if ($done) {
            HCYB_DB::kv_set('hcyb_fullscan_active', '0', 7*86400);
            HCYB_Logger::event(($changed+$missing+$susp)>0 ? 'med' : 'low','scanner','fullscan_done',[
                'message'=>'Zakończono pełny skan integralności.',
                'meta'=>['baseline_id'=>$baseline_id,'total'=>$total,'changed'=>$changed,'missing'=>$missing,'suspicious'=>$susp]
            ]);
        } else {
            // logujemy tylko gdy coś wykryto w ticku, żeby nie spamować
            if (($changed+$missing+$susp) > 0) {
                HCYB_Logger::event('med','scanner','fullscan_tick',[
                    'message'=>'Wykryto zmiany w trakcie pełnego skanu.',
                    'meta'=>['baseline_id'=>$baseline_id,'offset'=>$new_offset,'changed'=>$changed,'missing'=>$missing,'suspicious'=>$susp]
                ]);
            }
        }

        $st = self::fullscan_status();
        return [
            'done'=>$done,
            'checked'=>$checked,
            'changed'=>$changed,
            'missing'=>$missing,
            'suspicious'=>$susp,
            'status'=>$st,
        ];
    }

    /**
     * Lekki "pseudo-cron": jeśli pełny skan jest aktywny, wykonujemy mały tick
     * podczas zwykłego ruchu (bez WP-Cron i bez tabel WP).
     */
    public static function maybe_background_tick(): void {
        $active = (string)HCYB_DB::kv_get('hcyb_fullscan_active','0') === '1';
        if (!$active) return;
        $last = (int)HCYB_DB::kv_get('hcyb_fullscan_last_tick','0');
        // max 1 tick / 10s
        if ($last && (time() - $last) < 10) return;
        // tylko czasem, żeby nie obciążać
        if (random_int(1, 100) > 25) return; // 25%
        self::fullscan_tick(40);
    }
}
