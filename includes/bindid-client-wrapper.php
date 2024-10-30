<?php
/**
 * Plugin OIDC/oAuth client warpper class.
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
 * BindID_Client_Wrapper class.
 *
 * Plugin OIDC/oAuth client wrapper class.
 *
 * @package  BindID
 * @category Authentication
 */
class BindID_Client_Wrapper {

	/**
	 * The client object instance.
	 *
	 * @var BindID_Client
	 */
	private $client;

	/**
	 * The settings object instance.
	 *
	 * @var BindID_Option_Settings
	 */
	private $settings;

	/**
	 * The logger object instance.
	 *
	 * @var BindID_Option_Logger
	 */
	private $logger;

	/**
	 * Inject necessary objects and services into the client.
	 *
	 * @param BindID_Client          $client   A plugin client object instance.
	 * @param BindID_Option_Settings $settings A plugin settings object instance.
	 * @param BindID_Option_Logger   $logger   A plugin logger object instance.
	 */
	function __construct( BindID_Client $client, BindID_Option_Settings $settings, BindID_Option_Logger $logger ) {
		$this->client = $client;
		$this->settings = $settings;
		$this->logger = $logger;
	}

	/**
	 * Hook the client into WordPress.
	 *
	 * @param \BindID_Client          $client   The plugin client instance.
	 * @param \BindID_Option_Settings $settings The plugin settings instance.
	 * @param \BindID_Option_Logger   $logger   The plugin logger instance.
	 *
	 * @return \BindID_Client_Wrapper
	 */
	static public function register( BindID_Client $client, BindID_Option_Settings $settings, BindID_Option_Logger $logger ) {
		$client_wrapper  = new self( $client, $settings, $logger );

		// Alter the requests according to settings.
		add_filter( 'bindid-alter-request', array( $client_wrapper, 'alter_request' ), 10, 3 );

		if ( is_admin() ) {
			// Define handlers for bindid callback and bindid login
			add_action( 'wp_ajax_bindid-callback', array( $client_wrapper, 'authentication_request_callback' ), 10, 3 );
			add_action( 'wp_ajax_nopriv_bindid-callback', array( $client_wrapper, 'authentication_request_callback' ), 10, 3 );
			add_action( 'wp_ajax_bindid-login', array( $client_wrapper, 'authenticate' ), 10, 3 );
			add_action( 'wp_ajax_nopriv_bindid-login', array( $client_wrapper, 'authenticate' ), 10, 3 );
		}

		return $client_wrapper;
	}

	/**
	 * Start BindID authentication.
	 *
	 */
	function authenticate() {
		
		$auth_url = $this->get_authentication_url();
		
		if ( is_wp_error( $auth_url ) ) {
			$this->error_redirect( $auth_url );
		} else {
			nocache_headers();
			wp_redirect($auth_url);
		}

		exit;
	}

	/**
	 * Get the authentication url from the client.
	 *
	 * @return string|WP_Error
	 */
	function get_authentication_url() {
		return $this->client->make_authentication_url();
	}

	/**
	 * Handle errors by redirecting the user to the login form along with an
	 * error code
	 *
	 * @param WP_Error $error A WordPress error object.
	 *
	 * @return void
	 */
	function error_redirect( $error ) {
		$this->logger->log( $error );

		// Redirect user back to login page.
		wp_redirect(
			wp_login_url() .
			'?bindid-error-code=' . urlencode( $error->get_error_code() ) .
			'&bindid-error-message=' . urlencode( $error->get_error_message() )
		);
		exit;
	}

	/**
	 * Modify outgoing requests according to settings.
	 *
	 * @param array<mixed> $request   The outgoing request array.
	 * @param string       $operation The request operation name.
	 *
	 * @return mixed
	 */
	function alter_request( $request, $operation ) {
		$request['timeout'] = 30;
		return $request;
	}

	/**
	 * Control the authentication and subsequent authorization of the user when
	 * returning from the IDP.
	 *
	 * @return void
	 */
	function authentication_request_callback() {
	
		$client = $this->client;

		// Start the authentication flow.
		$session_info = $client->validate_authentication_response( $_GET );

		if ( is_wp_error( $session_info ) ) {
			$this->error_redirect( $session_info );
		}

		$authentication_response = $_GET;

		// Retrieve the authentication code from the authentication request.
		$code = $client->get_authentication_code( $authentication_response );

		if ( is_wp_error( $code ) ) {
			$this->error_redirect( $code );
		}

		// Attempting to exchange an authorization code for an authentication token.
		$token_result = $client->request_authentication_token( $code );

		if ( is_wp_error( $token_result ) ) {
			$this->error_redirect( $token_result );
		}

		// Get the decoded response from the authentication request result.
		$token_response = $client->get_token_response( $token_result );

		if ( is_wp_error( $token_response ) ) {
			$this->error_redirect( $token_response );
		}

		// Ensure the that response contains required information.
		$valid = $client->validate_token_response( $token_response );

		if ( is_wp_error( $valid ) ) {
			$this->error_redirect( $valid );
		}

		/**
		 * The id_token is used to identify the authenticated user, e.g. for SSO.
		 * The access_token must be used to prove access rights to protected
		 * resources e.g. for the userinfo endpoint
		 */
		$id_token_claim = $client->get_id_token_claim( $token_response );

		if ( is_wp_error( $id_token_claim ) ) {
			$this->error_redirect( $id_token_claim );
		}

		// Validate our id_token has required values.
		$valid = $client->validate_id_token_claim( $session_info, $id_token_claim );

		if ( is_wp_error( $valid ) ) {
			$this->error_redirect( $valid );
		}



		/**
		 * End authorization
		 * -
		 * Request is authenticated and authorized - start user handling
		 */
		
		$subject_identity = $client->get_subject_identity( $id_token_claim );
		$user = $this->get_user_by_identity( $subject_identity );

		if ( ! $user ) {
			$user = $this->create_new_user( $subject_identity, $id_token_claim );
			if ( is_wp_error( $user ) ) {
				$this->error_redirect( $user );
			}
		}

		// Validate the found / created user.
		$valid = $this->validate_user( $user );

		if ( is_wp_error( $valid ) ) {
			$this->error_redirect( $valid );
		}

		// Login the found / created user.
		$this->login_user( $user, $token_response, $id_token_claim, $subject_identity );

		// Log our success.
		$this->logger->log( "Successful login for: {$user->user_login} ({$user->ID})", 'login-success' );

		// Redirect back to the origin page if enabled.
		$redirect_url = isset( $_COOKIE[ $this->cookie_redirect_key ] ) ? esc_url_raw( $_COOKIE[ $this->cookie_redirect_key ] ) : false;

		wp_redirect( home_url() );

		exit;
	}

	/**
	 * Validate the potential WP_User.
	 *
	 * @param WP_User|WP_Error|false $user The user object.
	 *
	 * @return true|WP_Error
	 */
	function validate_user( $user ) {
		// Ensure the found user is a real WP_User.
		if ( ! is_a( $user, 'WP_User' ) || ! $user->exists() ) {
			return new WP_Error( 'invalid-user', __( 'Invalid user.', 'bindid' ), $user );
		}

		return true;
	}

	/**
	 * Record user meta data, and provide an authorization cookie.
	 *
	 * @param WP_User $user             The user object.
	 * @param array   $token_response   The token response.
	 * @param array   $id_token_claim   The ID token claim.
	 * @param string  $subject_identity The subject identity from the IDP.
	 *
	 * @return void
	 */
	function login_user( $user, $token_response, $id_token_claim, $subject_identity ) {
		// Store the tokens for future reference.
		update_user_meta( $user->ID, 'bindid-last-token-response', $token_response );
		update_user_meta( $user->ID, 'bindid-last-id-token-claim', $id_token_claim );

		// Create the WP session, so we know its token.
		$expiration = time() + apply_filters( 'auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user->ID, false );
		$manager = WP_Session_Tokens::get_instance( $user->ID );
		$token = $manager->create( $expiration );

		// you did great, have a cookie!
		wp_set_auth_cookie( $user->ID, false, '', $token );
		do_action( 'wp_login', $user->user_login, $user );
	}

	/**
	 * Get the user that has meta data matching a
	 *
	 * @param string $subject_identity The IDP identity of the user.
	 *
	 * @return false|WP_User
	 */
	function get_user_by_identity( $subject_identity ) {
		// Look for user by their bindid-subject-identity value.
		$user_query = new WP_User_Query(
			array(
				'meta_query' => array(
					array(
						'key'   => 'bindid-subject-identity',
						'value' => $subject_identity,
					),
				),
			)
		);

		// If we found an existing users, grab the first one returned.
		if ( $user_query->get_total() > 0 ) {
			$users = $user_query->get_results();
			return $users[0];
		}

		return false;
	}

	/**
	 * Get an email.
	 *
	 * @param array $id_token_claim           The authorized user claim.
	 *
	 * @return string|null
	 */
	private function get_email_from_claim( $id_token_claim) {
		$email = null;
		if (isset($id_token_claim['email']) &&
				isset($id_token_claim['email_verified']) &&
				$id_token_claim['email_verified'] === true) {
				$email = $id_token_claim['email'];
		}
		return $email;
	}

	/**
	 * Create a new user from details in a id_token_claim.
	 *
	 * @param string $subject_identity The authenticated user's identity with the IDP.
	 * @param array  $id_token_claim       id_token_claim claim.
	 *
	 * @return \WP_Error | \WP_User
	 */
	function create_new_user( $subject_identity, $id_token_claim ) {
		
		// Allow claim details to determine username, email, nickname and displayname.
		$email = $this->get_email_from_claim( $id_token_claim );
		if ( is_null( $email ) ) {
			return new WP_Error( 'no-verified-email-claim', __( 'No verified email.', 'bindid' ), $id_token_claim );
		}

		$username = $email;
		
		// Before trying to create the user, first check if a user with the same email already exists.
		$uid = email_exists( $email );
		if ( $uid ) {
			$user = $this->update_existing_user( $uid, $subject_identity );
			return $user;
		}

		$user_data = array(
			'user_login' => $username,
			'user_pass' => wp_generate_password( 32, true, true ),
			'user_email' => $email,
			'first_name' => isset( $id_token_claim['given_name'] ) ? $id_token_claim['given_name'] : '',
			'last_name' => isset( $id_token_claim['family_name'] ) ? $id_token_claim['family_name'] : '',
		);

		// Create the new user.
		$uid = wp_insert_user( $user_data );

		// Make sure we didn't fail in creating the user.
		if ( is_wp_error( $uid ) ) {
			return new WP_Error( 'user-creation-failed', __( 'Failed user creation.', 'bindid' ), $uid );
		}

		// Retrieve our new user.
		$user = get_user_by( 'id', $uid );

		// Save some meta data about this new user for the future.
		add_user_meta( $user->ID, 'bindid-subject-identity', (string) $subject_identity, true );

		// Log the results.
		$this->logger->log( "New user created: {$user->user_login} ($uid)", 'success' );

		return $user;
	}

	/**
	 * Update an existing user with OpenID Connect meta data
	 *
	 * @param int    $uid              The WordPress User ID.
	 * @param string $subject_identity The subject identity from the IDP.
	 *
	 * @return WP_Error|WP_User
	 */
	function update_existing_user( $uid, $subject_identity ) {
		// Add the OpenID Connect meta data.
		update_user_meta( $uid, 'bindid-subject-identity', strval( $subject_identity ) );

		// Return our updated user.
		return get_user_by( 'id', $uid );
	}
}
