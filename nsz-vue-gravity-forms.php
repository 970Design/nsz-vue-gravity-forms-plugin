<?php
/**
 *  Plugin Name: 970 Design Vue Gravity Forms
 *  Description: Secure proxy endpoints for headless Gravity Forms integration.
 *  Version:     1.3.2
 *  Author:      970 Design
 *  Author URI:  https://970design.com/
 *  License:     GPLv2 or later
 *  License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *  Text Domain: nsz-vue-gravity-forms
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once plugin_dir_path( __FILE__ ) . 'includes/class-base.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-admin.php';
require_once plugin_dir_path( __FILE__ ) . 'includes/class-api.php';

/**
 * Activation hook: generate API key if not present and set defaults
 */
function gf_headless_activate() {
	// Generate API key only if not present
	if ( ! get_option( 'gf_headless_api_key' ) ) {
		$key = wp_generate_password( 32, false );
		update_option( 'gf_headless_api_key', $key );
	}

	// Set default allowed origins (if not present)
	if ( get_option( 'gf_headless_allowed_origins' ) === false ) {
		update_option( 'gf_headless_allowed_origins', "http://localhost:4321\nhttp://localhost" );
	}

	if ( get_option( 'gf_headless_recaptcha_enabled' ) === false ) {
		update_option( 'gf_headless_recaptcha_enabled', '0' );
	}

	if ( get_option( 'gf_headless_recaptcha_site_key' ) === false ) {
		update_option( 'gf_headless_recaptcha_site_key', '' );
	}

	if ( get_option( 'gf_headless_recaptcha_secret_key' ) === false ) {
		update_option( 'gf_headless_recaptcha_secret_key', '' );
	}

	if ( get_option( 'gf_headless_recaptcha_threshold' ) === false ) {
		update_option( 'gf_headless_recaptcha_threshold', '0.5' );
	}
}

register_activation_hook( __FILE__, 'gf_headless_activate' );

add_action( 'plugins_loaded', function () {
	new GF_Headless_Api();
	new GF_Headless_Admin();
} );
