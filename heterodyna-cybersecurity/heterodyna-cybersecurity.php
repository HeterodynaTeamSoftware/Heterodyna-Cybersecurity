<?php
/*
Plugin Name: Heterodyna Cybersecurity
Description: Profesjonalna ochrona WordPress: WAF, hardening, nagłówki, logi zdarzeń, skaner integralności. Dane i konfiguracja w 100% we własnych tabelach.
Version: 01.001.0010
Author: Heterodyna Team Software
Author URI: https://heterodynateamsoftware.pl
Requires PHP: 8.0
*/

if (!defined('ABSPATH')) { exit; }

define('HCYB_VERSION', '01.001.0010');
define('HCYB_SLUG', 'heterodyna-cybersecurity');
define('HCYB_PATH', plugin_dir_path(__FILE__));
define('HCYB_URL', plugin_dir_url(__FILE__));

require_once HCYB_PATH . 'includes/class-hcyb-db.php';
require_once HCYB_PATH . 'includes/class-hcyb-policies.php';
require_once HCYB_PATH . 'includes/class-hcyb-privacy.php';
require_once HCYB_PATH . 'includes/class-hcyb-emergency.php';
require_once HCYB_PATH . 'includes/class-hcyb-adaptive.php';
require_once HCYB_PATH . 'includes/class-hcyb-logger.php';
require_once HCYB_PATH . 'includes/class-hcyb-alerts.php';
require_once HCYB_PATH . 'includes/class-hcyb-scanner.php';
require_once HCYB_PATH . 'includes/class-hcyb-reputation.php';
require_once HCYB_PATH . 'includes/class-hcyb-waf.php';
require_once HCYB_PATH . 'includes/class-hcyb-surface.php';
require_once HCYB_PATH . 'includes/class-hcyb-hardening.php';
require_once HCYB_PATH . 'includes/class-hcyb-admin.php';
require_once HCYB_PATH . 'includes/class-hcyb-login.php';
require_once HCYB_PATH . 'includes/class-hcyb-reports.php';
require_once HCYB_PATH . 'includes/class-hcyb-digest.php';

register_activation_hook(__FILE__, ['HCYB_DB', 'activate']);
register_deactivation_hook(__FILE__, ['HCYB_DB', 'deactivate']);

add_action('plugins_loaded', function() {
    HCYB_DB::init();
    HCYB_Privacy::init();
    HCYB_Emergency::init();
    HCYB_Logger::init();
    HCYB_Alerts::init();
    HCYB_Reputation::init();
    HCYB_Hardening::init();
    HCYB_WAF::init();
    HCYB_Login_Protect::init();
    HCYB_Digest::init();
    HCYB_Adaptive::init();
    HCYB_Scanner::maybe_background_tick();
    if (is_admin()) {
        HCYB_Admin::init();
    }
}, 0);

// (Opcjonalnie) MU-loader generator (dla WAF przed WordPress) - dostępny w Ustawieniach wtyczki.