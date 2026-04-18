<?php
/**
 * API class for GF Headless API
 * Handles REST routes, permissions, CORS, form schema, form submission, file uploads, and reCAPTCHA.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GF_Headless_Api extends GF_Headless_Base {

	public function __construct() {
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
		add_action( 'rest_api_init', [ $this, 'register_rest_cors' ] );

		// Enable SVG uploads for headless forms
		add_filter( 'upload_mimes', [ $this, 'add_svg_mime_type' ] );
		add_filter( 'wp_check_filetype_and_ext', [ $this, 'fix_svg_mime_type' ], 10, 4 );
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
						'required'          => true,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
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
						'required'          => true,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					],
				],
			]
		);

		// Get reCAPTCHA configuration (requires API key)
		register_rest_route(
			$this->api_namespace,
			'/recaptcha/config',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'get_recaptcha_config' ],
				'permission_callback' => [ $this, 'check_api_permission' ],
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

		$api_key = is_string( $api_key ) ? trim( $api_key ) : '';

		if ( ! $api_key || ! hash_equals( (string) $stored_key, (string) $api_key ) ) {
			return new WP_Error( 'unauthorized', 'Invalid API key', [ 'status' => 401 ] );
		}

		return true;
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
	 * Get reCAPTCHA configuration
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response
	 */
	public function get_recaptcha_config( $request ) {
		$enabled  = get_option( 'gf_headless_recaptcha_enabled', '0' ) === '1';
		$site_key = get_option( 'gf_headless_recaptcha_site_key', '' );

		return rest_ensure_response( [
			'enabled'  => $enabled,
			'site_key' => $enabled ? $site_key : '',
		] );
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
	 * Verify reCAPTCHA v3 token against Google's siteverify API.
	 * Returns WP_Error if verification fails or score is below threshold.
	 *
	 * @param string $token
	 * @return true|WP_Error
	 */
	private function verify_recaptcha( $token ) {
		$secret_key = get_option( 'gf_headless_recaptcha_secret_key', '' );

		if ( empty( $secret_key ) ) {
			return new WP_Error( 'recaptcha_misconfigured', 'reCAPTCHA secret key is not configured.', [ 'status' => 500 ] );
		}

		$response = wp_remote_post(
			'https://www.google.com/recaptcha/api/siteverify',
			[
				'timeout' => 10,
				'body'    => [
					'secret'   => $secret_key,
					'response' => $token,
					'remoteip' => $this->get_client_ip(),
				],
			]
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'recaptcha_request_failed', 'reCAPTCHA verification request failed.', [ 'status' => 500 ] );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body ) || ! isset( $body['success'] ) ) {
			return new WP_Error( 'recaptcha_invalid_response', 'Invalid reCAPTCHA response from Google.', [ 'status' => 500 ] );
		}

		if ( ! $body['success'] ) {
			$error_codes = isset( $body['error-codes'] ) ? implode( ', ', $body['error-codes'] ) : 'unknown';
			return new WP_Error( 'recaptcha_failed', 'reCAPTCHA verification failed: ' . $error_codes, [ 'status' => 400 ] );
		}

		$score = isset( $body['score'] ) ? (float) $body['score'] : 0.0;

		if ( $score < $this->get_recaptcha_threshold() ) {
			return new WP_Error(
				'recaptcha_score_too_low',
				'reCAPTCHA score too low. Possible bot activity detected.',
				[ 'status' => 400, 'score' => $score ]
			);
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

		$form = $this->decode_html_entities_recursive( $form );

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

			// reCAPTCHA verification - runs before any form processing
			$recaptcha_enabled = get_option( 'gf_headless_recaptcha_enabled', '0' ) === '1';

			if ( $recaptcha_enabled ) {
				$recaptcha_token = $request->get_param( 'recaptcha_token' );

				if ( empty( $recaptcha_token ) ) {
					return new WP_Error( 'recaptcha_missing', 'reCAPTCHA token is required.', [ 'status' => 400 ] );
				}

				$recaptcha_result = $this->verify_recaptcha( $recaptcha_token );

				if ( is_wp_error( $recaptcha_result ) ) {
					return $recaptcha_result;
				}
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

			// Process form fields (Gravity Forms stores fields as objects in $form['fields'])
			if ( isset( $form['fields'] ) && is_array( $form['fields'] ) ) {
				foreach ( $form['fields'] as $field ) {
					$field_id = is_object( $field ) ? $field->id : ( isset( $field['id'] ) ? $field['id'] : null );

					if ( $field_id === null ) {
						continue;
					}

					$field_type = is_object( $field ) ? $field->type : ( isset( $field['type'] ) ? $field['type'] : '' );

					// Handle different field types
					if ( $field_type === 'checkbox' || $field_type === 'multi_choice' ) {
						$input_type = is_object( $field )
							? ( $field->inputType ?? 'radio' )
							: ( $field['inputType'] ?? 'radio' );

						if ( $input_type === 'checkbox' ) {
							foreach ( $params as $param_key => $param_value ) {
								if ( preg_match( "/^input_{$field_id}_(\d+)$/", $param_key, $matches )
								     && $param_value !== ''
								     && $param_value !== null
								) {
									$entry_data[ $field_id . '.' . $matches[1] ] = sanitize_text_field( $param_value );
								}
							}
						} else {
							// Radio-backed: accept flat key
							$field_key = "input_{$field_id}";
							if ( isset( $params[ $field_key ] ) && $params[ $field_key ] !== '' ) {
								$entry_data[ $field_id ] = sanitize_text_field( $params[ $field_key ] );
							}
						}
					} elseif ( $field_type === 'multiselect' ) {
						$field_key = "input_{$field_id}";
						if ( isset( $params[ $field_key ] ) ) {
							$raw    = is_array( $params[ $field_key ] ) ? $params[ $field_key ] : [ $params[ $field_key ] ];
							$values = array_values( array_filter( array_map( 'sanitize_text_field', $raw ) ) );
							if ( ! empty( $values ) ) {
								$entry_data[ $field_id ] = implode( ',', $values );
							}
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
							// Merge into entry data with proper keys (using period separator)
							foreach ( $address_data as $sub_field => $value ) {
								$entry_data[ $field_id . '.' . $sub_field ] = $value;
							}
						}
					} elseif ( $field_type === 'name' ) {
						// Name fields: look for input_X_Y pattern where Y is the name component
						// Y can be: 2 (prefix), 3 (first), 4 (middle), 6 (last), 8 (suffix)
						$name_data = [];
						foreach ( $params as $param_key => $param_value ) {
							if ( preg_match( "/^input_{$field_id}_(\d+)$/", $param_key, $matches ) && ! empty( $param_value ) ) {
								$name_data[ $matches[1] ] = $param_value;
							}
						}
						if ( ! empty( $name_data ) ) {
							// Merge into entry data with proper keys (using period separator)
							foreach ( $name_data as $sub_field => $value ) {
								$entry_data[ $field_id . '.' . $sub_field ] = $value;
							}
						}
					} elseif ( $field_type === 'consent' ) {
						// WP REST API converts dots to underscores in param keys,
						// so input_11.1 arrives as input_11_1
						$consent_key_1 = "input_{$field_id}_1";
						$consent_key_2 = "input_{$field_id}_2";

						if ( isset( $params[ $consent_key_1 ] ) ) {
							$entry_data[ $field_id . '.1' ] = sanitize_text_field( $params[ $consent_key_1 ] );
						}
						if ( isset( $params[ $consent_key_2 ] ) ) {
							$entry_data[ $field_id . '.2' ] = sanitize_text_field( $params[ $consent_key_2 ] );
						}
					} elseif ( $field_type === 'fileupload' ) {
						// File upload fields - can be single or multiple
						$field_key = "input_{$field_id}";

						// Check if this is a multi-file upload field
						$is_multi = is_object( $field ) ?
							( isset( $field->multipleFiles ) ? $field->multipleFiles : false ) :
							( isset( $field['multipleFiles'] ) ? $field['multipleFiles'] : false );

						if ( $is_multi ) {
							// Handle multiple files - PHP converts input_X[0], input_X[1] into nested array format
							if ( isset( $uploaded_files[ $field_key ] ) ) {
								// Check if it's already in multi-file format (array of arrays)
								if ( isset( $uploaded_files[ $field_key ]['name'] ) && is_array( $uploaded_files[ $field_key ]['name'] ) ) {
									// Already in standard PHP multi-file format
									$files[ $field_id ] = $uploaded_files[ $field_key ];
								}
							}
						} else {
							// Single file upload
							if ( isset( $uploaded_files[ $field_key ] ) ) {
								$files[ $field_id ] = $uploaded_files[ $field_key ];
							}
						}
					} else if ( $field_type === 'image_choice' ) {
						$input_type = is_object( $field )
							? ( $field->inputType ?? 'radio' )
							: ( $field['inputType'] ?? 'radio' );

						if ( $input_type === 'checkbox' ) {
							foreach ( $params as $param_key => $param_value ) {
								if ( preg_match( "/^input_{$field_id}_(\d+)$/", $param_key, $matches )
								     && $param_value !== ''
								     && $param_value !== null
								) {
									$entry_data[ $field_id . '.' . $matches[1] ] = sanitize_text_field( $param_value );
								}
							}
						} else {
							$field_key = "input_{$field_id}";
							if ( isset( $params[ $field_key ] ) && $params[ $field_key ] !== '' ) {
								$entry_data[ $field_id ] = sanitize_text_field( $params[ $field_key ] );
							}
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

			// Handle file uploads and replace with saved file URLs
			if ( ! empty( $files ) ) {
				foreach ( $files as $field_id => $file_data ) {
					// Check if this is a multi-file upload (array of files)
					if ( is_array( $file_data ) && isset( $file_data['name'] ) && is_array( $file_data['name'] ) ) {
						// Multiple files
						$uploaded_files_json = [];
						$file_count          = count( $file_data['name'] );

						for ( $i = 0; $i < $file_count; $i++ ) {
							// Reconstruct individual file array
							$individual_file = [
								'name'     => $file_data['name'][ $i ],
								'type'     => $file_data['type'][ $i ],
								'tmp_name' => $file_data['tmp_name'][ $i ],
								'error'    => $file_data['error'][ $i ],
								'size'     => $file_data['size'][ $i ],
							];

							if ( $individual_file['error'] === 0 ) {
								$upload_result = $this->handle_file_upload( $individual_file, $form_id, $field_id );
								if ( ! is_wp_error( $upload_result ) ) {
									$uploaded_files_json[] = $upload_result['url']; // GF stores URLs in JSON array for multi-file
								} else {
									return $upload_result;
								}
							}
						}

						// Store as JSON array for Gravity Forms multi-file field
						$entry_data[ $field_id ] = wp_json_encode( $uploaded_files_json );

					} else {
						// Single file upload
						$upload_result = $this->handle_file_upload( $file_data, $form_id, $field_id );
						if ( ! is_wp_error( $upload_result ) ) {
							// For single file, store the relative path
							$entry_data[ $field_id ] = $upload_result['file'];
						} else {
							return $upload_result;
						}
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

			// Validate required fields
			$validation_messages = [];

			foreach ( $form['fields'] as $field ) {
				$field_id    = is_object( $field ) ? $field->id : $field['id'];
				$field_type  = is_object( $field ) ? $field->type : $field['type'];
				$is_required = is_object( $field ) ? ( $field->isRequired ?? false ) : ( $field['isRequired'] ?? false );

				if ( ! $is_required ) {
					continue;
				}

				$input_type = is_object( $field )
					? ( $field->inputType ?? '' )
					: ( $field['inputType'] ?? '' );

				$needs_dot_check = in_array( $field_type, [ 'name', 'address', 'consent', 'checkbox' ], true );

				if ( in_array( $field_type, [ 'multi_choice', 'image_choice' ], true ) ) {
					$needs_dot_check = ( $input_type === 'checkbox' );
				}

				if ( $needs_dot_check ) {
					$has_value = false;
					foreach ( $entry_data as $key => $val ) {
						if ( strpos( (string) $key, $field_id . '.' ) === 0 && ! empty( $val ) ) {
							$has_value = true;
							break;
						}
					}
					$empty = ! $has_value;
				} else {
					$value = $entry_data[ $field_id ] ?? null;
					$empty = is_null( $value ) || $value === '' || $value === [];
				}

				if ( $empty ) {
					$label                            = is_object( $field ) ? ( $field->label ?? '' ) : ( $field['label'] ?? '' );
					$validation_messages[ $field_id ] = sprintf( '%s is required.', $label );
				}
			}

			if ( ! empty( $validation_messages ) ) {
				return new WP_Error( 'validation_failed', 'Validation failed', [ 'status' => 400, 'validation_messages' => $validation_messages ] );
			}

			// Add entry to database
			$entry_id = GFAPI::add_entry( $entry );

			if ( is_wp_error( $entry_id ) ) {
				return new WP_Error( 'submission_failed', 'Failed to save entry', [ 'status' => 500 ] );
			}

			// Send notifications with proper error handling
			try {
				if ( isset( $form['notifications'] ) && ! empty( $form['notifications'] ) && class_exists( 'GFCommon' ) ) {
					$notifications_to_send = GFCommon::get_notifications_to_send( 'form_submission', $form, $entry );

					if ( ! empty( $notifications_to_send ) ) {
						foreach ( $notifications_to_send as $notification ) {
							GFCommon::send_notification( $notification, $form, $entry );
						}
					}
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
	 * Handle file upload - properly integrate with Gravity Forms file system
	 *
	 * @param array  $file
	 * @param int    $form_id
	 * @param string $field_id
	 * @return array|WP_Error Array with file info or WP_Error
	 */
	private function handle_file_upload( $file, $form_id, $field_id ) {
		if ( ! function_exists( 'wp_handle_upload' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		// Get the field to check allowed file types
		$form     = GFAPI::get_form( $form_id );
		$gf_field = null;

		if ( $form && isset( $form['fields'] ) ) {
			foreach ( $form['fields'] as $field_obj ) {
				$current_field_id = is_object( $field_obj ) ? $field_obj->id : $field_obj['id'];
				if ( $current_field_id == $field_id ) {
					$gf_field = $field_obj;
					break;
				}
			}
		}

		// Set up allowed file types based on field settings
		$allowed_extensions = [];
		if ( $gf_field ) {
			$allowed_extensions_setting = is_object( $gf_field ) ?
				( isset( $gf_field->allowedExtensions ) ? $gf_field->allowedExtensions : '' ) :
				( isset( $gf_field['allowedExtensions'] ) ? $gf_field['allowedExtensions'] : '' );

			if ( ! empty( $allowed_extensions_setting ) ) {
				$allowed_extensions = array_map( 'trim', explode( ',', $allowed_extensions_setting ) );
			}
		}

		// Validate file extension if field has restrictions
		if ( ! empty( $allowed_extensions ) ) {
			$file_extension = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
			if ( ! in_array( $file_extension, $allowed_extensions ) ) {
				return new WP_Error( 'invalid_file_type', 'File type not allowed.' );
			}
		}

		// Create Gravity Forms uploads directory if it doesn't exist
		$gf_upload_root     = rtrim( GFFormsModel::get_upload_root(), '/' );
		$gf_upload_url_root = rtrim( GFFormsModel::get_upload_url_root(), '/' );

		// Create form-specific directory
		$target_root     = $gf_upload_root . "/form_{$form_id}";
		$target_url_root = $gf_upload_url_root . "/form_{$form_id}";

		if ( ! wp_mkdir_p( $target_root ) ) {
			return new WP_Error( 'upload_dir_error', 'Could not create upload directory.' );
		}

		// Generate unique filename to prevent conflicts
		$original_name   = sanitize_file_name( $file['name'] );
		$unique_filename = wp_unique_filename( $target_root, $original_name );

		// Validate and move uploaded file
		$upload_overrides = [
			'test_form' => false,
			'mimes'     => $this->get_allowed_mime_types_for_upload(),
		];

		// Use wp_handle_upload but override the upload directory
		add_filter( 'upload_dir', function( $upload ) use ( $target_root, $target_url_root ) {
			return [
				'path'    => $target_root,
				'url'     => $target_url_root,
				'subdir'  => '',
				'basedir' => $target_root,
				'baseurl' => $target_url_root,
				'error'   => false,
			];
		}, 999 );

		$uploaded_file = wp_handle_upload( $file, $upload_overrides );

		// Remove the filter
		remove_all_filters( 'upload_dir', 999 );

		if ( isset( $uploaded_file['error'] ) ) {
			return new WP_Error( 'upload_failed', $uploaded_file['error'] );
		}

		// Return the file path (relative to wp-content) for Gravity Forms storage
		// Gravity Forms expects the file path relative to the uploads directory
		$relative_path = str_replace( WP_CONTENT_DIR . '/uploads/', '', $uploaded_file['file'] );

		// Remove any double slashes that might have been introduced
		$relative_path = preg_replace( '#/+#', '/', $relative_path );

		return [
			'file' => $relative_path, // This is what gets stored in the entry
			'url'  => $uploaded_file['url'],
			'type' => $uploaded_file['type'],
		];
	}

	/**
	 * Add SVG to allowed MIME types
	 *
	 * @param array $mimes
	 * @return array
	 */
	public function add_svg_mime_type( $mimes ) {
		$mimes['svg']  = 'image/svg+xml';
		$mimes['svgz'] = 'image/svg+xml';
		return $mimes;
	}

	/**
	 * Fix SVG MIME type detection
	 *
	 * @param array  $data
	 * @param string $file
	 * @param string $filename
	 * @param array  $mimes
	 * @return array
	 */
	public function fix_svg_mime_type( $data, $file, $filename, $mimes ) {
		$ext = isset( $data['ext'] ) ? $data['ext'] : '';

		if ( ! $ext ) {
			$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		}

		if ( $ext === 'svg' ) {
			$data['type'] = 'image/svg+xml';
			$data['ext']  = 'svg';
		} elseif ( $ext === 'svgz' ) {
			$data['type'] = 'image/svg+xml';
			$data['ext']  = 'svgz';
		}

		return $data;
	}

	/**
	 * Get allowed MIME types for file uploads (includes SVG support)
	 *
	 * @return array
	 */
	private function get_allowed_mime_types_for_upload() {
		$mimes = get_allowed_mime_types();

		// Add SVG support if not already present
		if ( ! isset( $mimes['svg'] ) ) {
			$mimes['svg'] = 'image/svg+xml';
		}
		if ( ! isset( $mimes['svgz'] ) ) {
			$mimes['svgz'] = 'image/svg+xml';
		}

		return $mimes;
	}
}
