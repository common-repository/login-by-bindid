<?php

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * Plugin OIDC/oAuth client class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Authentication
 * @author    Jonathan Daggerhart <jonathan@daggerhart.com>
 * @copyright 2015-2020 daggerhart
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 * 
 * @modified  Transmit Security
 * @copyright Transmit Security 2021 
 */

/**
 * BindID_Client class.
 *
 * Plugin BindID client class.
 *
 * @package  BindID
 * @category Authentication
 */
class BindID_Client {

	/**
	 * The BindID client ID.
	 *
	 * @see BindID_Option_Settings::client_id
	 *
	 * @var string
	 */
	private $client_id;

	/**
	 * The BindID client secret.
	 *
	 * @see BindID_Option_Settings::client_secret
	 *
	 * @var string
	 */
	private $client_secret;

	/**
	 * The BindID scopes.
	 *
	 * @var string
	 */
	private $scope;

	/**
	 * The BindID authorization endpoint URL.
	 *
	 * @var string
	 */
	private $endpoint_login;

	/**
	 * The BindID token exchange endpoint URL.
	 *
	 * @var string
	 */
	private $endpoint_token;


	/**
	 * The bindid JWKs uri.
	 *
	 * @var string
	 */
	private $jwks_uri;

	/**
	 * The login flow "ajax" endpoint URI.
	 *
	 * @var string
	 */
	private $redirect_uri;

	/**
	 * The session time limit. auth session are only valid for 3 minutes.
	 *
	 * @var int
	 */
	private $session_time_limit = 180;

	/**
	 * Enforce multifactor authentication.
	 *
	 * @see BindID_Option_Settings::enforce_multifactor
	 *
	 * @var bool
	 */
	private $enforce_multifactor = false;

	/**
	 * The logger object instance.
	 *
	 * @var BindID_Option_Logger
	 */
	private $logger;

	/**
	 * Client constructor.
	 *
	 * @param string                               $client_id         	@see BindID_Option_Settings::client_id for description.
	 * @param string                               $client_secret     	@see BindID_Option_Settings::client_secret for description.
	 * @param string                               $scope             	BindID oidc scope.
	 * @param string                               $endpoint_login    	BindID oidc authorization endpoint.
	 * @param string                               $endpoint_token    	BindID oidc token endpoint.
	 * @param string                               $jwks_uri    				BindID oidc jwks uri - for getting BindID public key.
	 * @param string                               $redirect_uri     		Oidc redirect uri
	 * @param int                                  $session_time_limit 	set BindID session time limit
	 * @param bool                                 $enforce_multifactor @see BindID_Option_Settings::enforce_multifactor for description.
	 * @param BindID_Option_Logger 								 $logger            	The plugin logging object instance.
	 */
	function __construct(
		$client_id,
		$client_secret,
		$scope,
		$endpoint_login,
		$endpoint_token,
		$jwks_uri,
		$redirect_uri,
		$session_time_limit,
		$enforce_multifactor,
		$logger ) {

		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->scope = $scope;
		$this->endpoint_login = $endpoint_login;
		$this->endpoint_token = $endpoint_token;
		$this->jwks_uri = $jwks_uri;
		$this->redirect_uri = $redirect_uri;
		$this->session_time_limit = $session_time_limit;
		$this->logger = $logger;
		$this->enforce_multifactor = $enforce_multifactor;
	}

	/**
	 * Create a single use authentication url
	 *
	 * @return string|WP_Error
	 */
	function make_authentication_url() {

		$endpoint_login = $this->endpoint_login;
		$scope = $this->scope;
		$client_id = $this->client_id;
		$redirect_uri = $this->redirect_uri;
		$acr_values = $this->build_acr_values();
		$state = $this->generate_random_string();
		$nonce = $this->generate_random_string();
		$is_set = $this->create_session($state, $nonce);
		if (!$is_set) {
			return new WP_Error( 'bindid-session-creation-failed', 'Failed to create bindid session.', $request );
		}

		$separator = '?';
		if ( stripos( $this->endpoint_login, '?' ) !== false ) {
			$separator = '&';
		}
		$url = sprintf(
			'%1$s%2$sresponse_type=code&scope=%3$s&client_id=%4$s&state=%5$s&nonce=%6$s&redirect_uri=%7$s&acr_values=%8$s',
			$endpoint_login,
			$separator,
			rawurlencode( $scope ),
			rawurlencode( $client_id ),
			$state,
			$nonce,
			rawurlencode( $redirect_uri ),
			$acr_values
		);

		$this->logger->log( $url , 'make_authentication_url' );
		return $url;
	}

	/**
	 * build acr_values for oidc auth request
	 *
	 * @param string $request The authentication request results.
	 *
	 * @return string acr_values
	 */
	function build_acr_values() {
		return 'ts.bindid.iac.email';
	}

	/**
	 * Validate authentication response
	 *
	 * @param array<string> $response The authentication response.
	 *
	 * @return array|WP_Error
	 */
	function validate_authentication_response( $response ) {
		// Look for an existing error of some kind.
		if ( isset( $response['error'] ) ) {
			return new WP_Error( 'auth-response-validation-failed', 'An unknown error occurred.', $response );
		}

		// Make sure we have a legitimate authentication code and valid state.
		if ( ! isset( $response['code'] ) ) {
			return new WP_Error( 'missing-authentication-code', 'No authentication code present in the request.', $response );
		}

		// Check the client request state.
		if ( ! isset( $response['state'] ) ) {
			return new WP_Error( 'missing-state', __( 'Missing state.', 'bindid' ), $response );
		}

		$state = $this->sanitize_base64code($response['state']);
		$session_info = $this->get_session_info($state);
		if (!$session_info) {
			return new WP_Error( 'invalid-state', __( 'Invalid state.', 'bindid' ), $response );
		}
		
		return $session_info;
	}

	/**
	 * Get the authorization code from the response
	 *
	 * @param array<string>|WP_Error $response The authentication response.
	 *
	 * @return string|WP_Error
	 */
	function get_authentication_code( $response ) {
		if ( ! isset( $response['code'] ) ) {
			return new WP_Error( 'missing-authentication-code', __( 'Missing authentication code.', 'bindid' ), $response );
		}
		return $this->sanitize_base64code($response['code']);
	}

	/**
	 * Using the authorization_code, request an authentication token from the IDP.
	 *
	 * @param string|WP_Error $code The authorization code.
	 *
	 * @return array<mixed>|WP_Error
	 */
	function request_authentication_token( $code ) {

		// Add Host header - required for when the openid-connect endpoint is behind a reverse-proxy.
		$parsed_url = parse_url( $this->endpoint_token );
		$host = $parsed_url['host'];

		$request = array(
			'body' => array(
				'code'          => $code,
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'redirect_uri'  => $this->redirect_uri,
				'grant_type'    => 'authorization_code',
				'scope'         => $this->scope,
			),
			'headers' => array( 'Host' => $host ),
		);

		// Allow modifications to the request.
		$request = apply_filters( 'bindid-alter-request', $request, 'get-authentication-token' );

		// Call the server and ask for a token.
		$this->logger->log( $this->endpoint_token, 'request_authentication_token' );
		$response = wp_remote_post( $this->endpoint_token, $request );

		if ( is_wp_error( $response ) ) {
			$response->add( 'request_authentication_token', __( 'Request for authentication token failed.', 'bindid' ) );
		}

		return $response;
	}

	/**
	 * Get jwks
	 *
	 * @return string|WP_Error
	 */
	function get_jwks() {
		
		$request = array();

		// Allow modifications to the request.
		$request = apply_filters( 'bindid-alter-request', $request, 'refresh-token' );

		// Call the server and ask for new tokens.
		$this->logger->log( $this->jwks_uri, 'request_jwks' );
		$response = wp_remote_get( $this->jwks_uri, $request );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'jwks-request-failure', __( 'Unable to get Jwks.', 'bindid' ), $response );
		}

		try {
			$json = json_decode( $response['body'] );
		} catch ( Exception $ex ) {
			return new WP_Error( 'jwks-decode-failure', __( 'Failed to decode jwks request.', 'bindid' ), $json );
		}

		try {
			$keys = array_map(function($key) { return (array)$key; }, $json->keys);
			$parsed_keys = JWK::parseKeySet(array('keys' => $keys));
		} catch ( Exception $ex ) {
			return new WP_Error( 'jwks-parsing-failure', __( 'Failed to parse Jwks.', 'bindid' ), array('keys' => $keys) );
		}

		return $parsed_keys;
	}

	/**
	 * Extract and decode the token body of a token response
	 *
	 * @param array<mixed>|WP_Error $token_result The token response.
	 *
	 * @return array<mixed>|WP_Error|null
	 */
	function get_token_response( $token_result ) {
		if ( ! isset( $token_result['body'] ) ) {
			return new WP_Error( 'missing-token-body', __( 'Missing token body.', 'bindid' ), $token_result );
		}

		// Extract the token response from token.
		$token_response = json_decode( $token_result['body'], true );

		// Check that the token response body was able to be parsed.
		if ( is_null( $token_response ) ) {
			return new WP_Error( 'invalid-token', __( 'Invalid token.', 'bindid' ), $token_result );
		}

		if ( isset( $token_response['error'] ) ) {
			$error = $token_response['error'];
			$error_description = $error;
			if ( isset( $token_response['error_description'] ) ) {
				$error_description = $token_response['error_description'];
			}
			return new WP_Error( $error, $error_description, $token_result );
		}

		return $token_response;
	}

	/**
	 * Generate a session, save it as a transient.
	 *
	 * @return bool
	 */
	private function create_session($state, $nonce) {
		$session_id = 'bindid-session--' . $state;
		return set_transient( $session_id, array( 'state' => $state, 'nonce' => $nonce) , $this->session_time_limit );
	}

	/**
	 * Generate a session, save it as a transient, and return the state hash.
	 *
	 * @return string
	 */
	private function delete_session($state) {
		delete_transient( 'bindid-session--' . $state );
	}


	/**
	 * Generate random string.
	 *
	 * @return string
	 */
	function generate_random_string() {
		$rbytes = random_bytes(32);
		return rtrim(strtr(base64_encode($rbytes), '+/', '-_'), '=');
	}

	/**
	 * Get session info by state.
	 *
	 * @param string state from response
	 *
	 * @return array | bool
	 */
	private function get_session_info( $state) {
		$session_info = get_transient( 'bindid-session--' . $state );
		if ($session_info) {
			$this->delete_session($state);
		}
		return $session_info;
	}

	/**
	 * Ensure that the token meets basic requirements.
	 *
	 * @param array $token_response The token response.
	 *
	 * @return bool|WP_Error
	 */
	function validate_token_response( $token_response ) {
		/*
		 * Ensure 2 specific items exist with the token response in order
		 * to proceed with confidence:  id_token and token_type == 'Bearer'
		 */
		if ( ! isset( $token_response['id_token'] ) ||
			 	! isset( $token_response['token_type'] ) || strcasecmp( $token_response['token_type'], 'Bearer' )
		) {
			return new WP_Error( 'invalid-token-response', 'Invalid token response', $token_response );
		}

		return true;
	}

	/**
	 * Extract the id_token_claim from the token_response.
	 *
	 * @param array $token_response The token response.
	 *
	 * @return array|WP_Error
	 */
	function get_id_token_claim( $token_response ) {
		// Validate there is an id_token.
		if ( ! isset( $token_response['id_token'] ) ) {
			return new WP_Error( 'no-identity-token', __( 'No identity token.', 'bindid' ), $token_response );
		}

		$keys = $this->get_jwks();
		if ( is_wp_error( $keys ) ) {
			return $keys;
		}

		try {
			return (array)JWT::decode($token_response['id_token'], $keys, array('RS256', 'RS384', 'RS512'));
		} catch ( Throwable $e ) {
			$message = $e->getMessage();
			$this->logger->log("id token validation failed; reason: [$message]", 'id-token-validation');
			return new WP_Error( 'id-token-validation', __( 'Failed to validate id-token.', 'bindid' ), $token_response );
		}

	}

	/**
	 * Ensure the id_token_claim contains the required values.
	 *
	 * @param string $state state from authorization response.
	 * @param array $id_token_claim The ID token claim.
	 *
	 * @return bool|WP_Error
	 */
	function validate_id_token_claim($session_info, $id_token_claim ) {
		
		if ( ! is_array( $id_token_claim ) ) {
			return new WP_Error( 'bad-id-token-claim', __( 'Bad ID token claim.', 'bindid' ), $id_token_claim );
		}

		$nonce = $id_token_claim['nonce'];

		if ( ! isset( $nonce ) || empty( $nonce ) ) {
			return new WP_Error( 'no-nonce', __( 'No nonce claim.', 'bindid' ), $id_token_claim );
		}

		$session_nonce = $session_info['nonce'];

		if ( ! isset( $session_nonce ) || empty( $session_nonce ) ) {
			return new WP_Error( 'no-session-nonce', __( 'No session nonce.', 'bindid' ), $id_token_claim );
		}

		if ( $nonce !== $session_nonce ) {
			return new WP_Error( 'invalid-nonce', __( 'Invalid nonce.', 'bindid' ), $id_token_claim );
		}

		if ($this->enforce_multifactor) {
			
			$amr = $id_token_claim['amr'];
			if ( ! isset( $amr ) || empty( $amr ) ) {
				return new WP_Error( 'no-amr', __( 'No amr claim.', 'bindid' ), $id_token_claim );
			}

			$is_multifactor = false;
			foreach ($amr as $amr_val) {
				if ($amr_val === 'ts.bind_id.mfuva' || $amr_val === 'ts.bind_id.mfca') {
					$is_multifactor = true;
					break;
				}
			}

			if (!$is_multifactor) {
				return new WP_Error( 'no-multifactor-auth', __( 'No multifactor authentication.', 'bindid' ), $id_token_claim );
			}

		}
		
		$audience = $id_token_claim['aud'];

		if ( ! isset( $audience ) || empty( $audience ) ) {
			return new WP_Error( 'no-audience', __( 'No audience.', 'bindid' ), $id_token_claim );
		}

		if (is_array($audience)) {
			$audience = $audience[0];
		}

		if ($audience !== $this->client_id) {
			return new WP_Error( 'invalid-audience', __( 'Invalid audience.', 'bindid' ), $id_token_claim );
		}

		// Validate the identification data and it's value.
		if ( ! isset( $id_token_claim['sub'] ) || empty( $id_token_claim['sub'] ) ) {
			return new WP_Error( 'no-subject-identity', __( 'No subject identity.', 'bindid' ), $id_token_claim );
		}

		return true;
	}

	/**
	 * Retrieve the subject identity from the id_token.
	 *
	 * @param array $id_token_claim The ID token claim.
	 *
	 * @return mixed
	 */
	function get_subject_identity( $id_token_claim ) {
		return $this->get_id_token_issuer( $id_token_claim ) . '@' . $id_token_claim['sub'];
	}

	/**
	 * Retrieve id token issuer.
	 *
	 * @return string id token issuer
	 */
	function get_id_token_issuer( $id_token_claim ) {
		return $id_token_claim['iss'];
	}

	/**
	 * sanitize base64 code.
	 *
	 * @return string sanitized code
	 */
	function sanitize_base64code( $key ) {
		return preg_replace( '/[^a-zA-Z0-9_\-]/', '', $key );
	}

}
