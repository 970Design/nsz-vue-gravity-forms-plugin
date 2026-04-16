<?php
/**
 * Base class for GF Headless API
 * Provides shared functionality for all classes.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class GF_Headless_Base {

	protected $api_namespace = 'gf-headless/v1';

	/**
	 * Recursively decode HTML entities in form schema
	 *
	 * @param mixed $data Form data (array, object, or string)
	 * @return mixed Decoded data
	 */
	protected function decode_html_entities_recursive( $data ) {
		if ( is_string( $data ) ) {
			return html_entity_decode( $data, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		}

		if ( is_array( $data ) ) {
			return array_map( [ $this, 'decode_html_entities_recursive' ], $data );
		}

		if ( is_object( $data ) ) {
			$decoded = clone $data;
			foreach ( $decoded as $key => $value ) {
				$decoded->$key = $this->decode_html_entities_recursive( $value );
			}
			return $decoded;
		}

		return $data;
	}

	/**
	 * Get client IP address
	 *
	 * @return string
	 */
	protected function get_client_ip() {
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
}
