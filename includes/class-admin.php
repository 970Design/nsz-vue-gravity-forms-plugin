<?php
/**
 * Admin class for GF Headless API
 * Handles admin menu, settings page, and plugin action links.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GF_Headless_Admin extends GF_Headless_Base {

	public function __construct() {
		add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_filter( 'plugin_action_links_' . plugin_basename( plugin_dir_path( dirname( __FILE__ ) ) . 'nsz-vue-gravity-forms.php' ), [ $this, 'add_plugin_action_links' ] );
	}

	/**
	 * Get reCAPTCHA v3 score threshold from settings.
	 * Falls back to 0.5 if the stored value is missing or out of the valid 0.0–1.0 range.
	 *
	 * @return float
	 */
	private function get_recaptcha_threshold() {
		$threshold = (float) get_option( 'gf_headless_recaptcha_threshold', 0.5 );
		return ( $threshold >= 0.0 && $threshold <= 1.0 ) ? $threshold : 0.5;
	}

	/**
	 * Add admin menu
	 */
	public function add_admin_menu() {
		add_options_page(
			'Gravity Forms Headless API Settings', // Page title
			'GF Headless API',                    // Menu title
			'manage_options',                     // Capability
			'gf-headless-settings',               // Menu slug
			[ $this, 'admin_page' ]               // Callback
		);
	}

	/**
	 * Register settings
	 */
	public function register_settings() {
		// Register with sanitization callbacks
		register_setting( 'gf_headless_settings', 'gf_headless_api_key', [
			'sanitize_callback' => 'sanitize_text_field',
		] );

		register_setting( 'gf_headless_settings', 'gf_headless_allowed_origins', [
			'sanitize_callback' => function ( $val ) {
				// Accept array or newline separated string; return newline separated sanitized string
				if ( is_array( $val ) ) {
					$val = implode( "\n", $val );
				}
				$lines = preg_split( '/\r\n|\r|\n/', (string) $val );
				$lines = array_map( 'trim', $lines );
				$lines = array_filter( $lines, function ( $v ) {
					return $v !== '';
				} );
				return implode( "\n", $lines );
			},
		] );

		register_setting( 'gf_headless_settings', 'gf_headless_recaptcha_enabled', [
			'sanitize_callback' => function ( $val ) {
				return $val === '1' ? '1' : '0';
			},
		] );

		register_setting( 'gf_headless_settings', 'gf_headless_recaptcha_site_key', [
			'sanitize_callback' => 'sanitize_text_field',
		] );

		register_setting( 'gf_headless_settings', 'gf_headless_recaptcha_secret_key', [
			'sanitize_callback' => 'sanitize_text_field',
		] );

		register_setting( 'gf_headless_settings', 'gf_headless_recaptcha_threshold', [
			'sanitize_callback' => function ( $val ) {
				$val = (float) $val;
				return ( $val >= 0.0 && $val <= 1.0 ) ? (string) $val : '0.5';
			},
		] );
	}

	/**
	 * Admin page
	 */
	public function admin_page() {
		$api_key              = get_option( 'gf_headless_api_key', '' );
		$origins_raw          = get_option( 'gf_headless_allowed_origins', "http://localhost:4321" );
		$recaptcha_enabled    = get_option( 'gf_headless_recaptcha_enabled', '0' );
		$recaptcha_site_key   = get_option( 'gf_headless_recaptcha_site_key', '' );
		$recaptcha_secret_key = get_option( 'gf_headless_recaptcha_secret_key', '' );
		?>
		<div class="wrap">
			<h1>Gravity Forms Headless API Settings</h1>

			<?php if ( $recaptcha_enabled === '1' && ( empty( $recaptcha_site_key ) || empty( $recaptcha_secret_key ) ) ) : ?>
				<div class="notice notice-warning">
					<p><strong>Warning:</strong> reCAPTCHA is enabled but one or both keys are missing. Form submissions will be rejected until both keys are configured.</p>
				</div>
			<?php elseif ( $recaptcha_enabled === '1' ) : ?>
				<div class="notice notice-success">
					<p><strong>reCAPTCHA v3 is active.</strong> All form submissions require a valid token with a score of <?php echo esc_html( $this->get_recaptcha_threshold() ); ?> or higher.</p>
				</div>
			<?php endif; ?>

			<form method="post" action="options.php">
				<?php settings_fields( 'gf_headless_settings' ); ?>
				<table class="form-table">
					<tr>
						<th scope="row">API Key</th>
						<td>
							<input type="text" name="gf_headless_api_key" value="<?php echo esc_attr( $api_key ); ?>" class="regular-text" required>
							<p class="description">API key is required for all API requests. Generated automatically on plugin activation.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Allowed Origins</th>
						<td>
							<textarea name="gf_headless_allowed_origins" class="large-text" rows="4"><?php echo esc_textarea( $origins_raw ); ?></textarea>
							<p class="description">One origin per line. Use * to allow all origins (not recommended for production). Example: http://localhost:4321</p>
						</td>
					</tr>
				</table>

				<h2>reCAPTCHA v3 Settings</h2>
				<p class="description">Server-side verification is performed on every form submission. Both keys are required when enabled. Get your keys from <a href="https://www.google.com/recaptcha/admin" target="_blank">Google reCAPTCHA Admin</a>.</p>
				<table class="form-table">
					<tr>
						<th scope="row">Enable reCAPTCHA v3</th>
						<td>
							<label>
								<input type="checkbox" name="gf_headless_recaptcha_enabled" value="1" <?php checked( $recaptcha_enabled, '1' ); ?>>
								Require reCAPTCHA v3 verification on all form submissions
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row">Site Key</th>
						<td>
							<input type="text" name="gf_headless_recaptcha_site_key" value="<?php echo esc_attr( $recaptcha_site_key ); ?>" class="regular-text">
							<p class="description">Your reCAPTCHA v3 site key (public — used by the frontend).</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Secret Key</th>
						<td>
							<input type="text" name="gf_headless_recaptcha_secret_key" value="<?php echo esc_attr( $recaptcha_secret_key ); ?>" class="regular-text">
							<p class="description">Your reCAPTCHA v3 secret key (private — never expose this to the frontend).</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Score Threshold</th>
						<td>
							<input
								type="number"
								name="gf_headless_recaptcha_threshold"
								value="<?php echo esc_attr( get_option( 'gf_headless_recaptcha_threshold', '0.5' ) ); ?>"
								class="small-text"
								min="0"
								max="1"
								step="0.1"
							>
							<p class="description">Minimum reCAPTCHA v3 score to accept. Default: 0.5.<br>
								(0.0 = all traffic (including bots), 1.0 = humans only).</p>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<h2>API Endpoints</h2>
			<p><strong>Get Form Schema:</strong> <code>GET /wp-json/gf-headless/v1/forms/{form_id}</code></p>
			<p><strong>Submit Form:</strong> <code>POST /wp-json/gf-headless/v1/forms/{form_id}/submit</code></p>
			<p><strong>Get reCAPTCHA Config:</strong> <code>GET /wp-json/gf-headless/v1/recaptcha/config</code></p>
			<p><strong>Note:</strong> All endpoints require a valid API key via the <code>X-API-Key</code> header or <code>api_key</code> parameter.</p>
		</div>
		<?php
	}

	/**
	 * Add settings link on plugin page
	 *
	 * @param array $links Existing plugin action links
	 * @return array Modified plugin action links
	 */
	public function add_plugin_action_links( $links ) {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=gf-headless-settings' ) ),
			esc_html__( 'Settings', 'nsz-vue-gravity-forms' )
		);

		// Add settings link at the beginning of the links array
		array_unshift( $links, $settings_link );

		return $links;
	}
}
