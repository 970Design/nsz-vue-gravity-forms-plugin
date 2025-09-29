<?php
/**
 *  Plugin Name: 970 Design Vue Gravity Forms (Headless)
 *  Description: Secure proxy endpoints for headless Gravity Forms integration.
 *  Version:     1.0
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

if ( ! class_exists( 'GF_Headless_API' ) ) {

	class GF_Headless_API {

		private $api_namespace = 'gf-headless/v1';

		public function __construct() {
			add_action( 'rest_api_init', [ $this, 'register_routes' ] );
			add_action( 'rest_api_init', [ $this, 'register_rest_cors' ] );
			add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
			add_action( 'admin_init', [ $this, 'register_settings' ] );
		}

		/**
		 * Activation hook: generate API key if not present and set defaults
		 */
		public static function activate() {
			// Generate API key only if not present
			if ( ! get_option( 'gf_headless_api_key' ) ) {
				$key = wp_generate_password( 32, false );
				update_option( 'gf_headless_api_key', $key );
			}

			// Set default allowed origins (if not present)
			if ( get_option( 'gf_headless_allowed_origins' ) === false ) {
				// store as newline separated string
				update_option( 'gf_headless_allowed_origins', "http://localhost:4321\nhttp://localhost" );
			}
		}

		/**
		 * Register REST API routes
		 */
		public function register_routes() {
			// Get form schema (requires API key)
			register_rest_route(
				$this->api_namespace,
				'/forms/(?P<form_id>\d+)',
				[
					'methods'             => 'GET',
					'callback'            => [ $this, 'get_form_schema' ],
					'permission_callback' => [ $this, 'check_api_permission' ],
					'args'                => [
						'form_id' => [
							'required'           => true,
							'type'               => 'integer',
							'sanitize_callback'  => 'absint',
						],
					],
				]
			);

			// Submit form (requires API key)
			register_rest_route(
				$this->api_namespace,
				'/forms/(?P<form_id>\d+)/submit',
				[
					'methods'             => 'POST',
					'callback'            => [ $this, 'submit_form' ],
					'permission_callback' => [ $this, 'check_api_permission' ],
					'args'                => [
						'form_id' => [
							'required'           => true,
							'type'               => 'integer',
							'sanitize_callback'  => 'absint',
						],
					],
				]
			);
		}

		/**
		 * Add CORS headers via rest_pre_serve_request filter (registered during rest_api_init)
		 */
		public function register_rest_cors() {
			add_filter(
				'rest_pre_serve_request',
				function ( $served, $result, $request ) {
					$this->send_cors_headers();
					return $served;
				},
				10,
				3
			);
		}

		/**
		 * Permission callback - always requires API key
		 *
		 * @param WP_REST_Request $request
		 * @return bool|WP_Error
		 */
		public function check_api_permission( $request ) {
			// Accept header X-API-Key or api_key param
			$api_key    = $request->get_header( 'X-API-Key' ) ?: $request->get_param( 'api_key' );
			$stored_key = get_option( 'gf_headless_api_key', '' );

			// sanitize
			$api_key = is_string( $api_key ) ? trim( $api_key ) : '';

			if ( ! $api_key || ! hash_equals( (string) $stored_key, (string) $api_key ) ) {
				return new WP_Error( 'unauthorized', 'Invalid API key', [ 'status' => 401 ] );
			}

			return true;
		}

		/**
		 * Get form schema
		 *
		 * @param WP_REST_Request $request
		 * @return WP_REST_Response|WP_Error
		 */
		public function get_form_schema( $request ) {
			$form_id = (int) $request->get_param( 'form_id' );

			if ( ! class_exists( 'GFAPI' ) ) {
				return new WP_Error( 'plugin_missing', 'Gravity Forms is not active', [ 'status' => 500 ] );
			}

			// Get form using GFAPI
			$form = GFAPI::get_form( $form_id );

			if ( ! $form || is_wp_error( $form ) ) {
				return new WP_Error( 'form_not_found', 'Form not found', [ 'status' => 404 ] );
			}

			// Check if form is active (note: GF forms use 'is_active' or 'is_trash' flags depending on GF version)
			if ( isset( $form['is_active'] ) && ! $form['is_active'] ) {
				return new WP_Error( 'form_inactive', 'Form is not active', [ 'status' => 403 ] );
			}

			// Cache the form schema (5 minutes)
			$cache_key   = "gf_headless_form_{$form_id}";
			$cached_form = wp_cache_get( $cache_key );

			if ( $cached_form !== false ) {
				return rest_ensure_response( $cached_form );
			}

			wp_cache_set( $cache_key, $form, '', 300 );

			return rest_ensure_response( $form );
		}

		/**
		 * Submit form
		 *
		 * @param WP_REST_Request $request
		 * @return WP_REST_Response|WP_Error
		 */
		public function submit_form( $request ) {
			try {
				$form_id = (int) $request->get_param( 'form_id' );

				if ( ! class_exists( 'GFAPI' ) ) {
					return new WP_Error( 'plugin_missing', 'Gravity Forms is not active', [ 'status' => 500 ] );
				}

				// Get form
				$form = GFAPI::get_form( $form_id );

				if ( ! $form || is_wp_error( $form ) ) {
					return new WP_Error( 'form_not_found', 'Form not found', [ 'status' => 404 ] );
				}

				if ( isset( $form['is_active'] ) && ! $form['is_active'] ) {
					return new WP_Error( 'form_inactive', 'Form is not active', [ 'status' => 403 ] );
				}

				// Build entry data array from request params
				$entry_data     = [];
				$files          = [];
				$params         = $request->get_params();
				$uploaded_files = $request->get_file_params();

				// Debug logging
				error_log( 'GF Headless: Form ID: ' . $form_id );
				error_log( 'GF Headless: Params: ' . print_r( $params, true ) );
				error_log( 'GF Headless: Files: ' . print_r( $uploaded_files, true ) );

				// Process form fields (Gravity Forms stores fields as objects in $form['fields'])
				if ( isset( $form['fields'] ) && is_array( $form['fields'] ) ) {
					foreach ( $form['fields'] as $field ) {
						$field_id = is_object( $field ) ? $field->id : ( isset( $field['id'] ) ? $field['id'] : null );

						if ( $field_id === null ) {
							continue;
						}

						$field_type = is_object( $field ) ? $field->type : ( isset( $field['type'] ) ? $field['type'] : '' );

						// Handle different field types
						if ( $field_type === 'checkbox' ) {
							// Checkbox fields: look for input_X_Y pattern
							$checkbox_values = [];
							foreach ( $params as $param_key => $param_value ) {
								if ( preg_match( "/^input_{$field_id}_(\d+)$/", $param_key ) && ! empty( $param_value ) ) {
									$checkbox_values[] = $param_value;
								}
							}
							if ( ! empty( $checkbox_values ) ) {
								$entry_data[ $field_id ] = $checkbox_values;
							}
						} elseif ( $field_type === 'multiselect' ) {
							// Multi-select fields: look for input_X[] pattern
							$field_key = "input_{$field_id}";
							if ( isset( $params[ $field_key ] ) && is_array( $params[ $field_key ] ) ) {
								$entry_data[ $field_id ] = $params[ $field_key ];
							}
						} elseif ( $field_type === 'address' ) {
							// Address fields: look for input_X_Y pattern where Y is the address component
							$address_data = [];
							foreach ( $params as $param_key => $param_value ) {
								if ( preg_match( "/^input_{$field_id}_(\d+)$/", $param_key, $matches ) && ! empty( $param_value ) ) {
									$address_data[ $matches[1] ] = $param_value;
								}
							}
							if ( ! empty( $address_data ) ) {
								// Merge into entry data with proper keys
								foreach ( $address_data as $sub_field => $value ) {
									$entry_data[ $field_id . '.' . $sub_field ] = $value;
								}
							}
						} elseif ( $field_type === 'consent' ) {
							// Consent fields: handle the checkbox and text parts
							$consent_key_1 = "input_{$field_id}.1";
							$consent_key_2 = "input_{$field_id}.2";

							if ( isset( $params[ $consent_key_1 ] ) ) {
								$entry_data[ $field_id . '.1' ] = $params[ $consent_key_1 ];
							}
							if ( isset( $params[ $consent_key_2 ] ) ) {
								$entry_data[ $field_id . '.2' ] = $params[ $consent_key_2 ];
							}
						} elseif ( $field_type === 'fileupload' ) {
							// File upload fields
							$field_key = "input_{$field_id}";
							if ( isset( $uploaded_files[ $field_key ] ) ) {
								$files[ $field_id ] = $uploaded_files[ $field_key ];
							}
						} else {
							// Simple fields (text, textarea, select, radio, etc.)
							$field_key = "input_{$field_id}";
							if ( isset( $params[ $field_key ] ) && $params[ $field_key ] !== '' ) {
								$entry_data[ $field_id ] = $params[ $field_key ];
							}
						}

						// Handle "other" choice if enabled
						$other_key = "input_{$field_id}_other";
						if ( isset( $params[ $other_key ] ) && ! empty( $params[ $other_key ] ) ) {
							$entry_data[ $field_id . '_other' ] = $params[ $other_key ];
						}
					}
				}

				// Handle file uploads and replace with saved file URLs (or file path if desired)
				if ( ! empty( $files ) ) {
					foreach ( $files as $field_id => $file ) {
						$upload_result = $this->handle_file_upload( $file, $form_id, $field_id );
						if ( ! is_wp_error( $upload_result ) ) {
							// store URL (you can store path if you prefer)
							$entry_data[ $field_id ] = $upload_result;
						} else {
							// return upload error
							return $upload_result;
						}
					}
				}

				// Build base entry array for GFAPI::add_entry
				$entry = [
					'form_id'      => $form_id,
					'date_created' => current_time( 'mysql' ),
					'is_starred'   => 0,
					'is_read'      => 0,
					'ip'           => $this->get_client_ip(),
					'source_url'   => $request->get_header( 'referer' ) ?: '',
					'user_agent'   => $request->get_header( 'user-agent' ) ?: '',
				];

				// Merge field values into entry
				foreach ( $entry_data as $field_id => $field_value ) {
					$entry[ $field_id ] = $field_value;
				}

				// Debug logging
				error_log( 'GF Headless: Entry data before submission: ' . print_r( $entry, true ) );

				// Validate the form using GFAPI::validate_form (returns array with is_valid and messages)
				$validation_result = [];
				if ( method_exists( 'GFAPI', 'validate_form' ) ) {
					// GFAPI::validate_form expects $form and array of values
					$validation_result = GFAPI::validate_form( $form, $entry_data );
				} else {
					// if validate_form is not available, we'll attempt no-op valid (best-effort)
					$validation_result = [ 'is_valid' => true ];
				}

				if ( isset( $validation_result['is_valid'] ) && ! $validation_result['is_valid'] ) {
					// Provide validation messages if available
					$messages = isset( $validation_result['validation_messages'] ) ? $validation_result['validation_messages'] : [];
					return new WP_Error( 'validation_failed', 'Validation failed', [ 'status' => 400, 'validation_messages' => $messages ] );
				}

				// Add entry to database
				$entry_id = GFAPI::add_entry( $entry );

				if ( is_wp_error( $entry_id ) ) {
					return new WP_Error( 'submission_failed', 'Failed to save entry', [ 'status' => 500 ] );
				}

				// Send notifications with proper error handling
				try {
					if ( class_exists( 'GFCommon' ) && method_exists( 'GFCommon', 'send_notifications' ) ) {
						// GFCommon::send_notifications requires 3+ parameters in newer GF versions
						$reflection = new ReflectionMethod( 'GFCommon', 'send_notifications' );
						$param_count = $reflection->getNumberOfRequiredParameters();

						if ( $param_count >= 3 ) {
							GFCommon::send_notifications( $form, $entry, 'form_submission' );
						} else {
							// Fallback for older GF versions (shouldn't happen with modern GF)
							GFCommon::send_notifications( $form, $entry );
						}
					} elseif ( method_exists( 'GFAPI', 'send_notifications' ) ) {
						GFAPI::send_notifications( $form, $entry, 'form_submission' );
					}
				} catch ( Exception $notification_error ) {
					// Log notification errors but don't fail the submission
					error_log( 'GF Headless: Notification error - ' . $notification_error->getMessage() );
				}

				// Get confirmation message (use GFFormDisplay if available)
				$confirmation = '';
				if ( class_exists( 'GFFormDisplay' ) && method_exists( 'GFFormDisplay', 'handle_confirmation' ) ) {
					$confirmation = GFFormDisplay::handle_confirmation( $form, $entry );
				}

				return rest_ensure_response(
					[
						'success'      => true,
						'entry_id'     => $entry_id,
						'confirmation' => $confirmation,
						'message'      => 'Form submitted successfully',
					]
				);
			} catch ( Exception $e ) {
				// Log the error for debugging
				error_log( 'GF Headless API Error: ' . $e->getMessage() );
				error_log( 'Stack trace: ' . $e->getTraceAsString() );

				return new WP_Error(
					'submission_error',
					'Form submission failed: ' . $e->getMessage(),
					[ 'status' => 500 ]
				);
			}
		}

		/**
		 * Handle file upload
		 *
		 * @param array  $file
		 * @param int    $form_id
		 * @param string $field_id
		 * @return string|WP_Error URL of uploaded file or WP_Error
		 */
		private function handle_file_upload( $file, $form_id, $field_id ) {
			if ( ! function_exists( 'wp_handle_upload' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}

			$upload_overrides = [
				'test_form' => false,
				'mimes'     => get_allowed_mime_types(),
			];

			$uploaded_file = wp_handle_upload( $file, $upload_overrides );

			if ( isset( $uploaded_file['error'] ) ) {
				return new WP_Error( 'upload_failed', $uploaded_file['error'] );
			}

			// Return the public URL to be stored in entry. You may prefer to store path instead.
			return $uploaded_file['url'];
		}

		/**
		 * Get client IP address
		 *
		 * @return string
		 */
		private function get_client_ip() {
			$ip_headers = [
				'HTTP_CF_CONNECTING_IP',
				'HTTP_CLIENT_IP',
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_FORWARDED',
				'HTTP_X_CLUSTER_CLIENT_IP',
				'HTTP_FORWARDED_FOR',
				'HTTP_FORWARDED',
				'REMOTE_ADDR',
			];

			foreach ( $ip_headers as $header ) {
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ip = $_SERVER[ $header ];
					if ( strpos( $ip, ',' ) !== false ) {
						$ip = explode( ',', $ip )[0];
					}
					return trim( $ip );
				}
			}

			return '';
		}

		/**
		 * Send CORS headers based on allowed origins option.
		 * Uses option stored as newline-separated string; normalizes to array.
		 */
		private function send_cors_headers() {
			$allowed = $this->get_allowed_origins_array();
			$origin  = isset( $_SERVER['HTTP_ORIGIN'] ) ? trim( (string) $_SERVER['HTTP_ORIGIN'] ) : '';

			// If allowed is empty (no origins configured) treat as allowing only same-origin (do nothing)
			if ( empty( $allowed ) ) {
				return;
			}

			$allow_all = in_array( '*', $allowed, true );

			// If credentials allowed, we cannot use wildcard '*'
			$allow_credentials = true;

			if ( $allow_all && $allow_credentials ) {
				// if wildcard but credentials true, must echo back origin rather than '*'
				$allow_origin = $origin ?: '*';
			} elseif ( $allow_all ) {
				$allow_origin = '*';
			} else {
				$allow_origin = in_array( $origin, $allowed, true ) ? $origin : '';
			}

			if ( $allow_origin ) {
				// Safe header sending (executed during rest_pre_serve_request)
				header( 'Access-Control-Allow-Origin: ' . $allow_origin );
				header( 'Access-Control-Allow-Methods: GET, POST, OPTIONS' );
				header( 'Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key' );
				if ( $allow_credentials ) {
					header( 'Access-Control-Allow-Credentials: true' );
				}
			}
		}

		/**
		 * Return allowed origins as an array (normalize newline-separated option)
		 *
		 * @return array
		 */
		private function get_allowed_origins_array() {
			$raw = get_option( 'gf_headless_allowed_origins', '' );

			if ( is_array( $raw ) ) {
				// legacy support if stored as array
				$origins = $raw;
			} else {
				$origins = preg_split( '/\r\n|\r|\n/', (string) $raw );
			}

			$origins = array_map( 'trim', (array) $origins );
			$origins = array_filter( $origins, function ( $v ) {
				return $v !== '';
			} );

			return array_values( $origins );
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
				[$this, 'admin_page']                 // Callback
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
		}

		/**
		 * Admin page
		 */
		public function admin_page() {
			$api_key     = get_option( 'gf_headless_api_key', '' );
			$origins_raw = get_option( 'gf_headless_allowed_origins', "http://localhost:4321" );
			?>
			<div class="wrap">
				<h1>Gravity Forms Headless API Settings</h1>
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
								<textarea name="gf_headless_allowed_origins" class="large-text" rows="4"><?php
									echo esc_textarea( $origins_raw );
									?></textarea>
								<p class="description">One origin per line. Use * to allow all origins (not recommended for production). Example: http://localhost:4321</p>
							</td>
						</tr>
					</table>
					<?php submit_button(); ?>
				</form>

				<h2>API Endpoints</h2>
				<p><strong>Get Form Schema:</strong> <code>GET /wp-json/gf-headless/v1/forms/{form_id}</code></p>
				<p><strong>Submit Form:</strong> <code>POST /wp-json/gf-headless/v1/forms/{form_id}/submit</code></p>
				<p><strong>Note:</strong> All endpoints require a valid API key via the <code>X-API-Key</code> header or <code>api_key</code> parameter.</p>
			</div>
			<?php
		}
	}
}

// Initialize the plugin and register activation hook
add_action( 'plugins_loaded', function () {
	global $gf_headless_api_instance;
	$gf_headless_api_instance = new GF_Headless_API();
} );

// Activation hook: use class static method
register_activation_hook( __FILE__, [ 'GF_Headless_API', 'activate' ] );
