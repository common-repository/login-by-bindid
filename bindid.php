<?php

/**
 * Login by BindID
 *
 * This plugin provides the ability to authenticate users with BindID
 * using the OpenID Connect OAuth2 API with Authorization Code Flow.
 * 
 * @package   OpenID_Connect_Generic
 * @category  General
 * @author    Jonathan Daggerhart <jonathan@daggerhart.com>
 * @copyright 2015-2020 daggerhart
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 * @link      https://github.com/daggerhart
 * 
 * @modified  Transmit Security
 * @copyright Transmit Security 2021 
 *
 * @wordpress-plugin
 * Plugin Name:       Login by BindID
 * Plugin URI:        https://github.com/TransmitSecurity/wordpress-bindid-integration
 * Description:       Login by BindId provides a seamless, passwordless login experience for your WordPress websites.
 * Version:           1.0.12
 * Author:            Transmit Security
 * Author URI:        https://www.transmitsecurity.com/
 * Text Domain:       bindid
 * Domain Path:       /languages
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI: https://github.com/TransmitSecurity/wordpress-bindid-integration
 */

/*
  User Meta
  - bindid-subject-identity    - the identity of the user provided by the idp
  - bindid-last-id-token-claim - the user's most recent id_token claim, decoded
  - bindid-last-token-response - the user's most recent token response
*/

require_once plugin_dir_path( __FILE__ ) . 'vendor/autoload.php';

define('BINDID_SESSION_TIME_LIMIT', 600);
define('BINDID_SCOPE', 'openid email');
define('BINDID_SIGNUP', 'https://www.transmitsecurity.com/developer?utm_signup=wp_store#try');
define('BINDID_DOCUMENTATION', 'https://developer.bindid.io/docs/guides/external_integrations/topics/integratingWordPress/integrating_with_wordpress');

/* Production Environment */
define('BINDID_AUTH_ENDPOINT', 'https://signin.identity.security/authorize');
define('BINDID_TOKEN_ENDPOINT', 'https://signin.identity.security/token');
define('BINDID_JWKS_URI', 'https://signin.identity.security/jwks');
define('BINDID_ADMIN_PORTAL', 'https://admin.bindid.io/console/#/applications');

/* Sandbox Environment */
define('BINDID_SANDBOX_AUTH_ENDPOINT', 'https://signin.bindid-sandbox.io/authorize');
define('BINDID_SANDBOX_TOKEN_ENDPOINT', 'https://signin.bindid-sandbox.io/token');
define('BINDID_SANDBOX_JWKS_URI', 'https://signin.bindid-sandbox.io/jwks');
define('BINDID_SANDBOX_ADMIN_PORTAL', 'https://admin.bindid-sandbox.io/console/#/applications');

/**
 * BindID class.
 *
 * Defines plugin initialization functionality.
 *
 * @package BindID
 * @category  General
 */
class BindID {

	/**
	 * Plugin version.
	 *
	 * @var
	 */
	const VERSION = '1.0.12';

	/**
	 * Plugin settings.
	 *
	 * @var BindID_Option_Settings
	 */
	private $settings;

	/**
	 * Plugin logs.
	 *
	 * @var BindID_Option_Logger
	 */
	private $logger;

	/**
	 * Setup the plugin
	 *
	 * @param BindID_Option_Settings $settings The settings object.
	 * @param BindID_Option_Logger   $logger   The loggin object.
	 *
	 * @return void
	 */
	function __construct( BindID_Option_Settings $settings, BindID_Option_Logger $logger ) {
		$this->settings = $settings;
		$this->logger = $logger;
	}

	/**
	 * WordPress Hook 'init'.
	 *
	 * @return void
	 */
	function init() {

		$redirect_uri = admin_url( 'admin-ajax.php?action=bindid-callback' );
		
		$client = new BindID_Client(
			$this->settings->client_id,
			$this->settings->client_secret,
			BINDID_SCOPE,
			( $this->settings->production_mode ) ? BINDID_AUTH_ENDPOINT : BINDID_SANDBOX_AUTH_ENDPOINT,
			( $this->settings->production_mode ) ? BINDID_TOKEN_ENDPOINT : BINDID_SANDBOX_TOKEN_ENDPOINT,
			( $this->settings->production_mode ) ? BINDID_JWKS_URI : BINDID_SANDBOX_JWKS_URI,
			$redirect_uri,
			BINDID_SESSION_TIME_LIMIT,
			$this->settings->enforce_multifactor,
			$this->logger
		);

		$client_wrapper = BindID_Client_Wrapper::register( $client, $this->settings, $this->logger );
	
		BindID_Login_Form::register( $this->settings, $client_wrapper, $logger );

		$this->upgrade();

		if ( is_admin() ) {
			add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'filter_plugin_actions'));
			BindID_Settings_Page::register( $this->settings, $this->logger );
		}
	}

	/**
	 * Filter plugin actions.
	 *
	 */
	public function filter_plugin_actions($links)
  {
		$settings_link = '<a href="options-general.php?page=bindid-settings">Settings</a>';
		array_unshift($links, $settings_link);
		return $links;
  }

	/**
	 * Handle plugin upgrades
	 *
	 * @return void
	 */
	function upgrade() {
		$last_version = get_option( 'bindid-plugin-version', 0 );
		$settings = $this->settings;

		if ( version_compare( self::VERSION, $last_version, '>' ) ) {
			// Update the stored version number.
			update_option( 'bindid-plugin-version', self::VERSION );
		}
	}

	/**
	 * Activation hook.
	 *
	 * @return void
	 */
	static public function activation() {
		
	}

	/**
	 * Deactivation hook.
	 *
	 * @return void
	 */
	static public function deactivation() {
		
	}

	/**
	 * Simple autoloader.
	 *
	 * @param string $class The class name.
	 *
	 * @return void
	 */
	static public function autoload( $class ) {
		
		$prefix = 'BindID_';

		if ( stripos( $class, $prefix ) !== 0 ) {
			return;
		}

		$filename = $class . '.php';

		// Internal files are all lowercase and use dashes in filenames.
		if ( false === strpos( $filename, '\\' ) ) {
			$filename = strtolower( str_replace( '_', '-', $filename ) );
		} else {
			$filename  = str_replace( '\\', DIRECTORY_SEPARATOR, $filename );
		}

		$filepath = dirname( __FILE__ ) . '/includes/' . $filename;

		if ( file_exists( $filepath ) ) {
			require_once $filepath;
		}
	}

	/**
	 * Instantiate the plugin and hook into WordPress.
	 *
	 * @return void
	 */
	static public function bootstrap() {
		
		spl_autoload_register( array( 'BindID', 'autoload' ) );

		$settings = new BindID_Option_Settings(
			'bindid_settings',
			array(
				'client_id'            	=> '',
				'client_secret'        	=> '',
				'enforce_multifactor' 	=> 0,
				'enable_logging'  		=> 0,
				'log_limit'       		=> 1000,
				'production_mode'		=> 0
			)
		);

		$logger = new BindID_Option_Logger( 'bindid-logs', 'error', $settings->enable_logging, $settings->log_limit );

		$plugin = new self( $settings, $logger );
		add_action( 'init', array( $plugin, 'init' ) );

	}
}

BindID::bootstrap();

register_activation_hook( __FILE__, array( 'BindID', 'activation' ) );
register_deactivation_hook( __FILE__, array( 'BindID', 'deactivation' ) );

?>