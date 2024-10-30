<?php
/**
 * Plugin Admin settings page class.
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
 * BindID_Settings_Page class.
 *
 * Admin settings page.
 *
 * @package BindID
 * @category  Settings
 */
class BindID_Settings_Page {

	/**
	 * Local copy of the settings provided by the base plugin.
	 *
	 * @var BindID_Option_Settings
	 */
	private $settings;

	/**
	 * Instance of the plugin logger.
	 *
	 * @var BindID_Option_Logger
	 */
	private $logger;

	/**
	 * The controlled list of settings & associated defined during
	 * construction for i18n reasons.
	 *
	 * @var array
	 */
	private $settings_fields = array();

	/**
	 * Options page slug.
	 *
	 * @var string
	 */
	private $options_page_name = 'bindid-settings';

	/**
	 * Options page settings group name.
	 *
	 * @var string
	 */
	private $settings_field_group;

	/**
	 * Settings page class constructor.
	 *
	 * @param BindID_Option_Settings $settings The plugin settings object.
	 * @param BindID_Option_Logger   $logger   The plugin logging class object.
	 */
	function __construct( BindID_Option_Settings $settings, BindID_Option_Logger $logger ) {

		$this->settings             = $settings;
		$this->logger               = $logger;
		$this->settings_field_group = $this->settings->get_option_name() . '-group';

		$fields = $this->get_settings_fields();

		// Some simple pre-processing.
		foreach ( $fields as $key => &$field ) {
			$field['key']  = $key;
			$field['name'] = $this->settings->get_option_name() . '[' . $key . ']';
		}

		// Allow alterations of the fields.
		$this->settings_fields = $fields;
	}

	/**
	 * Hook the settings page into WordPress.
	 *
	 * @param BindID_Option_Settings $settings A plugin settings object instance.
	 * @param BindID_Option_Logger   $logger   A plugin logger object instance.
	 *
	 * @return void
	 */
	static public function register( BindID_Option_Settings $settings, BindID_Option_Logger $logger ) {
		$settings_page = new self( $settings, $logger );

		// Add our options page the the admin menu.
		add_action( 'admin_menu', array( $settings_page, 'admin_menu' ) );

		// Register our settings.
		add_action( 'admin_init', array( $settings_page, 'admin_init' ) );
	}

	/**
	 * Implements hook admin_menu to add our options/settings page to the
	 *  dashboard menu.
	 *
	 * @return void
	 */
	public function admin_menu() {
		add_options_page(
			__( 'Login by BindID', 'bindid' ),
			__( 'Login by BindID', 'bindid' ),
			'manage_options',
			$this->options_page_name,
			array( $this, 'settings_page' )
		);
	}

	/**
	 * Implements hook admin_init to register our settings.
	 *
	 * @return void
	 */
	public function admin_init() {
		register_setting(
			$this->settings_field_group,
			$this->settings->get_option_name(),
			array(
				$this,
				'sanitize_settings',
			)
		);

		add_settings_section(
			'client_settings',
			null,
			null,
			$this->options_page_name
		);

		if ($this->is_debug_mode()) {
			add_settings_section(
				'log_settings',
				__( 'Log Settings', 'bindid' ),
				array( $this, 'log_settings_description' ),
				$this->options_page_name
			);
		}

		// Preprocess fields and add them to the page.
		foreach ( $this->settings_fields as $key => $field ) {

			// Make sure each key exists in the settings array.
			if ( ! isset( $this->settings->{ $key } ) ) {
				$this->settings->{ $key } = null;
			}

			// Determine appropriate output callback.
			switch ( $field['type'] ) {
				case 'toggle':
						$callback = 'do_toggle';
						break;

				case 'select':
					$callback = 'do_select';
					break;

				case 'text':
				default:
					$callback = 'do_text_field';
					break;
			}

			// Add the field.
			add_settings_field(
				$key,
				$field['title'],
				array( $this, $callback ),
				$this->options_page_name,
				$field['section'],
				$field
			);
		}
	}

	/**
	 * Ary we in debug mode.
	 *
	 * @return bool
	 */
	private function is_debug_mode() {
		return ($_GET['bindid-debug'] === 'true');
	}

	/**
	 * Get the plugin settings fields definition.
	 *
	 * @return array
	 */
	private function get_settings_fields() {

		$client_secret_saved = $this->client_secret_saved();

		/**
		 * Simple settings fields have:
		 *
		 * - title
		 * - description
		 * - type ( toggle | number | text | select )
		 * - section - settings/option page section ( client_settings | authorization_settings )
		 * - example (optional example will appear beneath description and be wrapped in <code>)
		 */
		$fields = array(
			'client_id'    	=> array(
				'title'       => __( 'Client ID', 'bindid' ),
				'description' => __( 'Client ID found in your application settings in the', 'bindid' ),
				'type'        => 'text',
				'section'     => 'client_settings',
				'isMandatory' => true,
				'withLink'		=> true,
				'link'			=> $this->get_bindid_admin_portal(( $this->settings->production_mode ) ? true : false ),
				'linkLabel'		=> $this->get_bindid_admin_portal_label()
			),
			'client_secret'   => array(
				'title'       => __( 'Client secret', 'bindid' ),
				'description' => __( 'Client secret found in your application settings in the', 'bindid' ),
				'type'        => 'text',
				'mask'				=> $client_secret_saved,
				'section'     => 'client_settings',
				'saved'				=> $client_secret_saved,
				'isMandatory' => !$client_secret_saved,
				'withLink'		=> true,
				'link'				=> $this->get_bindid_admin_portal(( $this->settings->production_mode ) ? true : false ),
				'linkLabel'		=> $this->get_bindid_admin_portal_label()
			),
			'enforce_multifactor'    => array(
				'title'       => __( 'Require strong authentication', 'bindid' ),
				'description' => __( 'Require biometric authentication using a trusted device.', 'bindid' ),
				'type'        => 'toggle',
				'section'     => 'client_settings',
			),
			'enable_logging'  => array(
				'title'       => __( 'Enable Logging', 'bindid' ),
				'description' => __( 'Very simple log messages for debugging purposes.', 'bindid' ),
				'type'        => 'toggle',
				'section'     => 'log_settings',
			),
			'log_limit'       => array(
				'title'       => __( 'Log Limit', 'bindid' ),
				'description' => __( 'Number of items to keep in the log. These logs are stored as an option in the database, so space is limited.', 'bindid' ),
				'type'        => 'number',
				'section'     => 'log_settings',
			),
			'production_mode'    => array(
				'title'       => __( 'Production mode', 'bindid' ),
				'description' => __( 'Run this plugin in your BindID production environment.', 'bindid' ),
				'type'        => 'toggle',
				'section'     => 'client_settings',
			)
		);

		return $fields;

	}

	/**
	 * Sanitization callback for settings/option page.
	 *
	 * @param array $input The submitted settings values.
	 *
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$options = array();

		// Loop through settings fields to control what we're saving.
		foreach ( $this->settings_fields as $key => $field ) {
			if ( isset( $input[ $key ] ) ) {
				$options[ $key ] = sanitize_text_field( trim( $input[ $key ] ) );
			} else {
				$options[ $key ] = '';
			}
		}

		return $options;
	}

	/**
	 * Output the options/settings page.
	 *
	 * @return void
	 */
	public function settings_page() {

		$redirect_uri = admin_url( 'admin-ajax.php?action=bindid-callback' );
		?>
		<div class="wrap">
			<?php echo $this->get_style() ?>
			<h1><?php echo esc_html( __( 'Login by BindID Settings', 'bindid' ) ); ?></h1>
			<br>
			<?php echo $this->get_signup_section() ?>
			<form class="bindid-settings-form" method="post" action="options.php">
				<?php
					settings_fields( $this->settings_field_group );
					do_settings_sections( $this->options_page_name );
				?>
				<p>
					<?php
						echo esc_html($this->client_settings_description());
						echo $this->buildLink(BINDID_DOCUMENTATION, $this->get_documantation_link_label());echo '.';
					?>
				</p>
				<?php
					submit_button();
					// Simple debug to view settings array.
					if ( $_GET['bindid-debug'] === 'true' ) {
						$values = $this->settings->get_values();
						unset($values['client_secret']);
						var_dump( $values );
					}
				?>
			</form>

			<?php if ( $this->settings->enable_logging && $this->is_debug_mode() ) { ?>
				<h2><?php echo esc_html(__( 'Logs', 'bindid' )); ?></h2>
				<div id="logger-table-wrapper">
					<?php echo $this->logger->get_logs_table(); ?>
				</div>

			<?php } ?>
		</div>
		<?php
	}

	/**
	 * Output a standard text field.
	 *
	 * @param array $field The settings field definition array.
	 *		<input type="<?php echo esc_attr( $field['type'] ); ?>"

	 * @return void
	 */
	public function do_text_field( $field ) {
		?>
		<input type="<?php echo esc_attr( $field['type'] ); ?>"
				<?php echo $field['isMandatory'] === true ? 'required ' : ''; ?>
				<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) ) ? ' disabled' : ''; ?>
				id="<?php echo esc_attr( $field['key'] ); ?>"
				class="large-text<?php echo ( ! empty( $field['disabled'] ) && boolval( $field['disabled'] ) ) ? ' disabled' : ''; ?>"
				name="<?php echo esc_attr( $field['name'] ); ?>"
				value="<?php echo $field['mask'] === true ? '**********' : esc_attr( $this->settings->{ $field['key'] } ); ?>"
				>
		<?php
		$this->do_field_description( $field, $is_visible );
	}

	/**
	 * Output a toggle button for a boolean setting.
	 *  - hidden field is default value so we don't have to check isset() on save.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_toggle( $field ) {
		?>
		<input type="hidden" name="<?php echo esc_attr( $field['name'] ); ?>" value="0">
		<label
			class="bindid-toggle-button">
			<input type="checkbox"
				id="<?php echo esc_attr( $field['key'] ); ?>"
				name="<?php echo esc_attr( $field['name'] ); ?>"
				value="1"
				<?php checked( $this->settings->{ $field['key'] }, 1 ); ?>>
			<span></span>
		</label>
		<?php
		$this->do_field_description( $field, true );
	}

	function client_secret_saved() {
		return !empty(trim($this->settings->client_secret));
	}

	/**
	 * Output a select control.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	function do_select( $field ) {
		$current_value = isset( $this->settings->{ $field['key'] } ) ? $this->settings->{ $field['key'] } : '';
		?>
		<select name="<?php echo esc_attr( $field['name'] ); ?>">
			<?php foreach ( $field['options'] as $value => $text ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $value, $current_value ); ?>><?php echo esc_html( $text ); ?></option>
			<?php endforeach; ?>
		</select>
		<?php
		$this->do_field_description( $field );
	}

	/**
	 * Output the field description, and example if present.
	 *
	 * @param array $field The settings field definition array.
	 *
	 * @return void
	 */
	public function do_field_description( $field, $same_line = false ) {
		?>
		<p class="description <?php echo $same_line ? 'bindid-sameline-description' : '' ?>">
			<?php echo esc_html($field['description']); ?>
			<?php 
				if ($field['withLink'] === true) {
					echo ' ';
					echo $this->buildLink($field['link'], $field['linkLabel']);echo '.';
				}
			?>
			<?php if ( isset( $field['example'] ) ) : ?>
				<br/><strong><?php echo esc_html(__( 'Example', 'bindid' )); ?>: </strong>
				<code><?php echo esc_html($field['example']); ?></code>
			<?php endif; ?>
		</p>
		<?php
	}

	/**
	 * Output the 'Client Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function client_settings_description() {
		return __( 'Need help? See BindID ', 'bindid' );
	}

	/**
	 * Output the 'Log Settings' plugin setting section description.
	 *
	 * @return void
	 */
	public function log_settings_description() {
		echo esc_html(__( 'Log information about login attempts through BindID.', 'bindid' ));
	}

	/**
	 * Get bindid documentation link's label.
	 *
	 * @return string
	 */
	private function get_documantation_link_label() {
		return __( 'documentation', 'bindid' );
	}

	/**
	 * build link
	 *
	 * @return void
	 */
	private function buildLink($href, $label) {
		?><a href="<?php echo esc_attr($href) ?>"><?php echo esc_html( $label ); ?></a><?php
	}

	/**
	 * get bindid admin portal url
	 *
	 * @return string
	 */
	private function get_bindid_admin_portal($production_mode) {
		return ($production_mode) ? BINDID_ADMIN_PORTAL : BINDID_SANDBOX_ADMIN_PORTAL;
	}

	
	/**
	 * get bindid admin portal label
	 *
	 * @return string
	 */
	private function get_bindid_admin_portal_label() {
		return __( 'BindID Admin Portal', 'bindid' );
	}

	/**
	 * get bindid setting page style
	 *
	 * @return void
	 */
	private function get_style() {
		?>
		<style type="text/css">

			.bindid-sameline-description {
				display: inline-block;
			}

			.bindid-settings-form	input:invalid {
				border: 1px solid red;
			}

			.bindid-signup-section {
				border-left: 4px solid #72aee6;
				padding: 12px;
				margin-left: 0;
				margin-bottom: 20px;
				background-color: #fff;
				box-shadow: 0 1px 1px 0 rgb(0 0 0 / 10%);
			}

			.bindid-toggle-button span:after {
				background: #fff;
				border-radius: 11px;
				height: 22px;
				width: 22px;
				border: 2px solid lightgray;
				box-sizing: border-box;
			}

			.bindid-toggle-button input:checked + span:after {
					right: 0;
					border-color: limegreen;
			}

			.bindid-toggle-button span:before, .bindid-toggle-button span:after {
					content: "";
					position: absolute;
			}

			.bindid-toggle-button span:before {
					background: lightgray;
					height: 100%;
					border-radius: 13px;
					width: 100%;
					border: 2px solid lightgray;
					box-sizing: border-box;
			}

			.bindid-toggle-button input:checked + span:before {
					background: limegreen;
					border-color: limegreen;
			}

			.bindid-toggle-button input {
					height: 0;
					left: 0;
					opacity: .0001;
					position: absolute;
					top: 0;
					width: 0;
					padding: 0;
					margin: 0;
			}

			.bindid-toggle-button {
					width: 40px;
					height: 22px;
					display: block;
					position: relative;
					display: inline-block;
					margin-right: 10px;
			}

			.bindid-signup-button, .bindid-important-message {
				vertical-align: middle !important;
			}

			.bindid-signup-button a {
				text-decoration: none;
			}
			a:focus {
				outline: none;
			}

		</style>
		<?php
	}

	/**
	 * get signup section
	 *
	 * @return void
	 */
	private function get_signup_section() {
		?>
		<div class="bindid-signup-section">
			<span class="bindid-important-message">
				<strong><?php echo esc_html( __('Important', 'bindid') ); ?>:</strong>
				<?php echo esc_html( __('This plugin requires a BindID tenant.', 'bindid') ); ?>
			</span>
			<button 
				class="bindid-signup-button button button-secondary"
				onclick="window.location.assign('<?php echo esc_attr(BINDID_SIGNUP) ?>')"
				>
				<?php echo esc_html( __('Sign up for free', 'bindid') ); ?>
			</button>
		</div>
		<?php
	}

} 
