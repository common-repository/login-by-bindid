<?php
/**
 * WordPress options handling class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Settings
 * @author    Jonathan Daggerhart <jonathan@daggerhart.com>
 * @copyright 2015-2020 daggerhart
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 * 
 * @modified  Transmit Security
 * @copyright Transmit Security 2021 
 */

/**
 * BindID_Option_Settings class.
 *
 * WordPress options handling.
 *
 * @package BindID
 * @category  Settings
 *
 * OAuth Client Settings:
 *
 * @property string $client_id            The ID the client will be recognized as when connecting the to Identity provider server.
 * @property string $client_secret        The secret key the IDP server expects from the client.
  *
 * Plugin Settings:
 *
 * @property bool $enforce_multifactor   		The flag to indicate whether to enfore multifactor authentication.
 * @property bool $enable_logging           The flag to enable/disable logging.
 * @property int  $log_limit                The maximum number of log entries to keep.
 */
class BindID_Option_Settings {

	/**
	 * WordPress option name/key.
	 *
	 * @var string
	 */
	private $option_name;

	/**
	 * Stored option values array.
	 *
	 * @var array<mixed>
	 */
	private $values;

	/**
	 * Default plugin settings values.
	 *
	 * @var array<mixed>
	 */
	private $default_settings;

	/**
	 * The class constructor.
	 *
	 * @param string       $option_name       The option name/key.
	 * @param array<mixed> $default_settings  The default plugin settings values.
	 * @param bool         $granular_defaults The granular defaults.
	 */
	function __construct( $option_name, $default_settings = array(), $granular_defaults = true ) {
		$this->option_name = $option_name;
		$this->default_settings = $default_settings;
		$this->values = array();

		if ( ! empty( $this->option_name ) ) {
			$this->values = (array) get_option( $this->option_name, $this->default_settings );
		}

		if ( $granular_defaults ) {
			$this->values = array_replace_recursive( $this->default_settings, $this->values );
		}

		if (!empty(trim($this->values['client_secret']))) {
			$this->values['client_secret'] = $this->decrypt_secret($this->values['client_secret']);
		}
		
		add_filter( 'pre_update_option_bindid_settings' , array($this, 'modify_settings') , 10, 3 ); 
	}

	/**
	 * Magic getter for settings.
	 *
	 * @param string $key The array key/option name.
	 *
	 * @return mixed
	 */
	function __get( $key ) {
		if ( isset( $this->values[ $key ] ) ) {
			return $this->values[ $key ];
		}
	}

	/**
	 * Magic setter for settings.
	 *
	 * @param string $key   The array key/option name.
	 * @param mixed  $value The option value.
	 *
	 * @return void
	 */
	function __set( $key, $value ) {
		$this->values[ $key ] = $value;
	}

	/**
	 * Magic method to check is an attribute isset.
	 *
	 * @param string $key The array key/option name.
	 *
	 * @return bool
	 */
	function __isset( $key ) {
		return isset( $this->values[ $key ] );
	}

	/**
	 * Magic method to clear an attribute.
	 *
	 * @param string $key The array key/option name.
	 *
	 * @return void
	 */
	function __unset( $key ) {
		unset( $this->values[ $key ] );
	}

	/**
	 * Get the plugin settings array.
	 *
	 * @return array
	 */
	function get_values() {
		$values_copy = array();
		foreach ($this->values as $k => $v) {
			$values_copy[$k] = $v;
		}
		return $values_copy;
	}

	/**
	 * Get the plugin WordPress options name.
	 *
	 * @return string
	 */
	function get_option_name() {
		return $this->option_name;
	}

	/**
	 * Modify settings value before saving to db.
	 *
	 * @return mixed modified value
	 */
	function modify_settings($value, $old_value, $option) {
		$trimed_value = trim($value['client_secret']);
		if ($this->isNewPassword($trimed_value) ) {
			$value['client_secret'] = $this->encrypt_secret($trimed_value);
		} else {
			$value['client_secret'] = $old_value['client_secret'];
		}
		return $value;
	}

	/**
	 * Check if the user specified new password.
	 *
	 * @return boolean
	 */
	private function isNewPassword($value) {
		return !empty($value) && !preg_match("/^\*+$/", $value);
	}

	/**
	 * Ectrypt client secret using AUTH_KEY and AUTH_SALT.
	 *
	 * @return string ecrypted client secret
	 */
	private function encrypt_secret($secret) {
		global $wpdb;
		$key = hash('sha256', AUTH_KEY);
		$iv = substr(hash('sha256', AUTH_SALT), 0, 16);
		return base64_encode(openssl_encrypt($secret, 'AES-256-CBC', $key, 0, $iv));
	}

	/**
	 * Dectrypt client secret using AUTH_KEY and AUTH_SALT.
	 *
	 * @return string decrypted client secret
	 */
	private function decrypt_secret($secret ) {
		global $wpdb;
		$key = hash('sha256', AUTH_KEY);
		$iv = substr(hash('sha256', AUTH_SALT), 0, 16);
		return openssl_decrypt(base64_decode($secret), 'AES-256-CBC' ,$key, 0, $iv);
	}

}
