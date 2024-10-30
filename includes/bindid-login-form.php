<?php
/**
 * Login form and login button handlong class.
 *
 * @package   OpenID_Connect_Generic
 * @category  Login
 * @author    Jonathan Daggerhart <jonathan@daggerhart.com>
 * @copyright 2015-2020 daggerhart
 * @license   http://www.gnu.org/licenses/gpl-2.0.txt GPL-2.0+
 * 
 * @modified  Transmit Security
 * @copyright Transmit Security 2021 
 */

/**
 * BindID_Login_Form class.
 *
 * Login form and login button handlong.
 *
 * @package BindID
 * @category  Login
 */
class BindID_Login_Form {

	/**
	 * Plugin settings object.
	 *
	 * @var BindID_Option_Settings
	 */
	private $settings;

	/**
	 * Plugin client wrapper instance.
	 *
	 * @var BindID_Client_Wrapper
	 */
	private $client_wrapper;

	/**
	 * The logger object instance.
	 *
	 * @var BindID_Option_Logger
	 */
	private $logger;


	/**
	 * The class constructor.
	 *
	 * @param BindID_Option_Settings $settings       A plugin settings object instance.
	 * @param BindID_Client_Wrapper  $client_wrapper A plugin client wrapper object instance.
	 */
	function __construct( $settings, $client_wrapper, $logger) {
		$this->logger = $logger;
		$this->settings = $settings;
		$this->client_wrapper = $client_wrapper;
	}

	/**
	 * Create an instance of the BindID_Login_Form class.
	 *
	 * @param BindID_Option_Settings $settings       A plugin settings object instance.
	 * @param BindID_Client_Wrapper  $client_wrapper A plugin client wrapper object instance.
	 *
	 * @return void
	 */
	static public function register( $settings, $client_wrapper, $logger ) {
		$login_form = new self( $settings, $client_wrapper, $logger  );

		add_filter( 'login_message', array( $login_form, 'handle_login_message' ), 99 );
		add_filter( 'login_form', array( $login_form, 'handle_login_form' ), 99 );
		add_action( 'login_footer', array( $login_form, 'handle_login_footer' ), 99 );

		// Add a shortcode for the login button.
		add_shortcode( 'bindid_login_button', array( $login_form, 'add_login_button' ) );

	}

	/**
	 * Implements filter login_message.
	 *
	 * @param string $message The text message to display on the login page.
	 *
	 * @return string
	 */
	function handle_login_message( $message ) {
		
		if ( isset( $_GET['bindid-error-code'] ) ) {
			$message .= $this->make_error_output(
				sanitize_text_field($_GET['bindid-error-code']),
				sanitize_text_field($_GET['bindid-error-message'])
			);
		}

		return $message;
	}

	/**
	 * Implements filter login_form.
	 */
	function handle_login_form() {
		if ( ! isset( $_GET['action'] ) || $_GET['action'] === 'login' ) {
			echo $this->add_login_button();
			echo $this->add_toggle_classic_login();
		}
	}


	/**
	 * Implements filter login_footer.
	 */
	function handle_login_footer() {
		
		if ( ! isset( $_GET['action'] ) || $_GET['action'] === 'login' ) {
			echo $this->add_script();
		}
	}

	/**
	 * add bindid login page script.
	 */
	function add_script() {

		$bindid_classic_mode = $_GET['bindid-classic-visible'] === 'true' ? 'false' : 'true';

		ob_start();
		?>
		<script>
			function bindid_toggle_classic_login() {
				function toggle(element) {
					element.style.display = document.body.dataset.bindid_classic_mode === 'true'  ? 'none' : 'block';
				}				
				var user = document.getElementById('user_login');
				user && user.parentElement && toggle(user.parentElement);
				var password = document.getElementsByClassName('user-pass-wrap')[0];
				password && toggle(password);
				var passwordInput = document.getElementById('user_pass');
				if (passwordInput) passwordInput.disabled = false;
				var forgetmenot = document.getElementsByClassName('forgetmenot')[0];
				forgetmenot && toggle(forgetmenot);
				var submit = document.getElementsByClassName('submit')[0];
				submit && toggle(submit);
				var nav = document.getElementById('nav');
				nav && toggle(nav);
				document.body.dataset.bindid_classic_mode = document.body.dataset.bindid_classic_mode === 'true' ? 'false' : 'true' ;
			};
			(function() {
				var login_form = document.getElementById('loginform');
				var toggle_classic = document.getElementsByClassName('bindid-toggle-classic-login-container')[0];
				login_form.insertBefore(toggle_classic, login_form.childNodes[0]);
				var bindid_button = document.getElementsByClassName('bindid-login-button')[0];
				login_form.insertBefore(bindid_button, login_form.childNodes[0]);
				document.body.dataset.bindid_classic_mode = <?php echo $bindid_classic_mode ?>;
				bindid_toggle_classic_login();
			})();
		</script>
		<?php
		return ob_get_clean();
	}


	/**
	 * Display an error message to the user.
	 *
	 * @param string $error_code    The error code.
	 * @param string $error_message The error message test.
	 *
	 * @return string
	 */
	function make_error_output( $error_code, $error_message ) {

		ob_start();
		?>
		<div id="login_error">
			<strong><?php printf( esc_html(__( 'ERROR (%1$s)', 'bindid' )), esc_html($error_code)); ?>: </strong>
			<?php echo esc_html( $error_message ); ?>
		</div>
		<?php
		return ob_get_clean();
	}


	/**
	 * make user credentials toggle button.
	 *
	 * @return string
	 */
	function add_toggle_classic_login(  ) {

		$text = __( 'Toggle Classic Login', 'bindid' );

		ob_start();
		?>
		<style type="text/css">
			.bindid-toggle-classic-login-container {
				text-align: center;
				margin-top: 1em;
				margin-bottom: 2em;
			}
			.bindid-toggle-classic-login {
				font-size: 13px;
  			color: #1c2745;
				text-decoration: none;
			}
		</style>
		<div class="bindid-toggle-classic-login-container">
			<a href="#" class="bindid-toggle-classic-login" onclick="bindid_toggle_classic_login();this.blur();"><?php echo esc_html($text); ?></a>
		</div>
		<?php
		return ob_get_clean();
	}

	/**
	 * Create a login button (link).
	 *
	 * functionality when used by shortcode.
	 *
	 * @return string
	 */
	function add_login_button() {
		$text = __( 'Login with BindID', 'bindid' );
		$href = $this->get_login_url();

		ob_start();
		?>
		<style type="text/css">
			.bindid-login-button {
				margin-top: 1em;
				text-align: center;
			}
			.bindid-login-button .button {
				width: 100%;
				font-size: 14px;
				font-weight: 600;
				color: #1c2745;
				border-radius: 4px;
  			box-shadow: 0 2px 8px 0 rgba(28, 39, 69, 0.08), 0 -2px 8px 0 rgba(28, 39, 69, 0.08);
  			border: solid 1px rgba(28, 39, 69, 0.37);
  			background-color: #ffffff;
			}
			.bindid-login-button .button:hover, .bindid-login-button .button:focus {
				color: #1c2745;
  			border: solid 1px rgba(28, 39, 69, 0.37);
			}
			.bindid-icon {
				margin-right: 5px;
    		margin-bottom: -4px;
			}
		</style>
		<div class="bindid-login-button">
			<a class="button button-large" href="<?php echo esc_url( $href ); ?>">
			<img class="bindid-icon" src="data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' width='19' height='18' viewBox='0 0 19 18'%3e%3cg fill='none' fill-rule='evenodd'%3e%3cg fill-rule='nonzero'%3e%3cg%3e%3cg%3e%3cg fill='%231C2745'%3e%3cpath d='M.006 9.037L.006.006.691.006.691 9.037zM10.53 4.42c.05 2.297-1.42 4.617-4.591 4.617H2.873V.006h3.066c3.066 0 4.54 2.193 4.59 4.413zM3.574.666v7.697H5.94c2.69 0 3.928-2.01 3.889-3.945C9.789 2.535 8.546.667 5.938.667H3.575z' transform='translate(-999 -854) translate(986 846) translate(13.856 8) translate(3.724 4.345)'/%3e%3c/g%3e%3cpath fill='%23FC335F' d='M17.438 13.09c.312 0 .562.251.562.562v2.274c.006 1.14-.928 2.074-2.074 2.074h-2.274c-.31 0-.561-.25-.561-.562 0-.31.25-.561.561-.561h2.274c.523 0 .95-.428.95-.95v-2.275c0-.31.251-.561.562-.561zm-16.876 0c.31 0 .561.25.561.562v2.271c0 .522.428.95.95.95h2.275c.31 0 .561.25.561.56 0 .312-.245.567-.556.567H2.08C.934 18 0 17.067 0 15.923v-2.271c0-.311.25-.561.562-.561zM15.923 0C17.067 0 18 .934 18 2.08v2.273c0 .306-.25.556-.56.556-.312 0-.562-.25-.562-.561V2.074c0-.523-.427-.951-.95-.951h-2.276c-.311 0-.561-.25-.561-.561 0-.312.25-.562.56-.562h2.272zM4.348 0c.311 0 .561.25.561.56 0 .312-.25.562-.56.562H2.076c-.522 0-.95.427-.95.95v2.27c0 .317-.255.567-.566.567C.25 4.91 0 4.66 0 4.35V2.076C0 .933.933 0 2.077 0h2.271z' transform='translate(-999 -854) translate(986 846) translate(13.856 8)'/%3e%3c/g%3e%3c/g%3e%3c/g%3e%3c/g%3e%3c/svg%3e"></span>
			<?php echo esc_html($text); ?></a>
		</div>
		<?php
		return ob_get_clean();
	}

	/**
	 * return bindid login page url
	 *
	 * @return string
	 */
	function get_login_url() {
		return admin_url( 'admin-ajax.php?action=bindid-login' );
	}

}
