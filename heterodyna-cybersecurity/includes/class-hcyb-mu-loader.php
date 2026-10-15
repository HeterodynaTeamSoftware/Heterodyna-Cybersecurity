<?php
if (!defined('ABSPATH')) { exit; }

class HCYB_MU_Loader {
    public static function generate(): array {
        $mu_dir = WP_CONTENT_DIR . '/mu-plugins';
        if (!is_dir($mu_dir)) {
            @mkdir($mu_dir, 0755, true);
        }
        if (!is_dir($mu_dir) || !is_writable($mu_dir)) {
            return ['ok'=>false,'message'=>'Katalog wp-content/mu-plugins nie jest zapisywalny. Utwórz go ręcznie i nadaj uprawnienia.'];
        }

        $file = $mu_dir . '/heterodyna-cybersecurity-loader.php';
        $content = <<<'PHP'
<?php
// MU-loader: Heterodyna Cybersecurity
// Ten plik ładuje WAF możliwie wcześnie (przed standardowymi wtyczkami).
if (!defined('ABSPATH')) exit;
if (defined('HCYB_MU_LOADER')) return;
define('HCYB_MU_LOADER', true);

$plugin = WP_PLUGIN_DIR . '/heterodyna-cybersecurity/heterodyna-cybersecurity.php';
if (file_exists($plugin)) {
  require_once $plugin;
}
PHP;
        $ok = (bool)file_put_contents($file, $content);
        if (!$ok) return ['ok'=>false,'message'=>'Nie udało się zapisać pliku MU-loader.'];
        return ['ok'=>true,'message'=>'MU-loader wygenerowany: wp-content/mu-plugins/heterodyna-cybersecurity-loader.php'];
    }
}
