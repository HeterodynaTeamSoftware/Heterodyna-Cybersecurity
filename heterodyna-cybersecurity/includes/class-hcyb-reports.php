<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_Reports {
    public static function summary(int $days = 7): array {
        if ($days < 1) $days = 1;
        global $wpdb;
        [$t_events,] = HCYB_DB::tables()['events'];
        $cut = gmdate('Y-m-d H:i:s', time() - ($days * 86400));

        $total = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $t_events WHERE created_at >= %s", $cut));
        $by_level = $wpdb->get_results($wpdb->prepare("SELECT level, COUNT(*) c FROM $t_events WHERE created_at >= %s GROUP BY level ORDER BY c DESC", $cut), ARRAY_A);
        $by_cat = $wpdb->get_results($wpdb->prepare("SELECT category, COUNT(*) c FROM $t_events WHERE created_at >= %s GROUP BY category ORDER BY c DESC", $cut), ARRAY_A);
        $top_ip = $wpdb->get_results($wpdb->prepare("SELECT ip, COUNT(*) c FROM $t_events WHERE created_at >= %s AND ip IS NOT NULL AND ip<>'' GROUP BY ip ORDER BY c DESC LIMIT 10", $cut), ARRAY_A);
        $top_path = $wpdb->get_results($wpdb->prepare("SELECT path, COUNT(*) c FROM $t_events WHERE created_at >= %s AND path IS NOT NULL AND path<>'' GROUP BY path ORDER BY c DESC LIMIT 10", $cut), ARRAY_A);

        return [
            'days' => $days,
            'cut' => $cut,
            'total' => $total,
            'by_level' => $by_level,
            'by_category' => $by_cat,
            'top_ip' => $top_ip,
            'top_path' => $top_path,
        ];
    }

    public static function render_html(int $days = 7): string {
        $s = self::summary($days);
        $site = get_site_url();
        $html = '';
        $html .= '<h2>Heterodyna Cybersecurity – Raport</h2>';
        $html .= '<p><strong>Serwis:</strong> ' . esc_html($site) . '<br>';
        $html .= '<strong>Okres:</strong> ostatnie ' . (int)$s['days'] . ' dni (od ' . esc_html($s['cut']) . ' UTC)</p>';
        $html .= '<p><strong>Łącznie zdarzeń:</strong> ' . (int)$s['total'] . '</p>';

        $html .= '<h3>Poziomy</h3>';
        $html .= self::table(['Poziom','Liczba'], array_map(function($r){return [$r['level'], $r['c']];}, $s['by_level']));

        $html .= '<h3>Kategorie</h3>';
        $html .= self::table(['Kategoria','Liczba'], array_map(function($r){return [$r['category'], $r['c']];}, $s['by_category']));

        $html .= '<h3>Top IP</h3>';
        $html .= self::table(['IP','Liczba'], array_map(function($r){return [$r['ip'], $r['c']];}, $s['top_ip']));

        $html .= '<h3>Top ścieżki</h3>';
        $html .= self::table(['Ścieżka','Liczba'], array_map(function($r){return [$r['path'], $r['c']];}, $s['top_path']));

        $html .= '<hr><p>Wygenerowano: ' . esc_html(gmdate('Y-m-d H:i:s')) . ' UTC</p>';
        return $html;
    }

    private static function table(array $headers, array $rows): string {
        $out = '<table class="widefat striped"><thead><tr>';
        foreach ($headers as $h) $out .= '<th>' . esc_html($h) . '</th>';
        $out .= '</tr></thead><tbody>';
        if (!$rows) {
            $out .= '<tr><td colspan="' . count($headers) . '">Brak danych</td></tr>';
        } else {
            foreach ($rows as $r) {
                $out .= '<tr>';
                foreach ($r as $cell) $out .= '<td>' . esc_html((string)$cell) . '</td>';
                $out .= '</tr>';
            }
        }
        $out .= '</tbody></table>';
        return $out;
    }
}
