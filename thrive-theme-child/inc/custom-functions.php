<?php
/**
 * Create the admin page 
 **/ 
function fs_admin_menu() {
	add_menu_page(
        __( 'Fusepress External Settings'),
        __( 'Fusepress External Settings'),
		'manage_options',
        'fusepress_settings',
        'fp_admin_page_contents',
        'dashicons-admin-generic',
    );
}
add_action('admin_menu', 'fs_admin_menu');

/**
 * Fusepress admin page content 
 **/ 
function fp_admin_page_contents() {

	if(isset($_POST['fp_settings'])){
		$fp_settings = $_POST['fp_settings'];
		if(!empty($fp_settings)){
			update_option('fp_settings', $fp_settings);
		}
	}
	$fp_settings = get_option('fp_settings');
	
    if(empty($fp_settings)){
        $fp_settings = array(
            'general_settings' => array(
                'page_links' => array(
                    'login' => 0,
                    'dashboard' => 0,
                    'welcome' => 0,
                ), 
            )
        );
    }?>

    <div class="wrap">
        <h1><?php _e('Fusepress Front Setting'); ?></h1>
        <?php $pages = get_pages(); ?>
        <form method="post">
            <table class="form-table">
                <tr valign="top">
                    <th scope="row"><?php _e('Select Login Page:'); ?></th>
                    <td>
                        <select name="fp_settings[general_settings][page_links][login]" id="option_etc">
                            <option><?php _e('Select Page'); ?></option>
                            <?php
								if(!empty($pages)){ 
									foreach ($pages as $page) { ?>
                                		<option value="<?php echo $page->ID; ?>" <?php echo (($fp_settings['general_settings']['page_links']['login'] == $page->ID) ? 'selected' : '') ?>><?php echo $page->post_name; ?></option>
                            			<?php 
									} 
								} 
							?>
                        </select>
                    </td>
                </tr>
                
                <tr valign="top">
                    <th scope="row"><?php _e('Select Dashboard Page:'); ?></th>
                    <td>
                        <select name="fp_settings[general_settings][page_links][dashboard]" id="option_etc">
                            <option><?php _e('Select Page'); ?></option>
                            <?php 
								if(!empty($pages)){ 
									foreach ($pages as $page) { ?>
                                		<option value="<?php echo $page->ID; ?>" <?php echo (($fp_settings['general_settings']['page_links']['dashboard'] == $page->ID) ? 'selected' : '') ?>><?php echo $page->post_name; ?></option>
										<?php 
									} 
								} 
							?>
                        </select>
                    </td>
                </tr>
                
                <tr valign="top">
                    <th scope="row"><?php _e('Select Welcome Page:'); ?></th>
                    <td>
                        <select name="fp_settings[general_settings][page_links][welcome]" id="option_etc">
                            <option><?php _e('Select Page'); ?></option>
                            <?php 
								if(!empty($pages)){ 
									foreach ($pages as $page) { ?>
                                		<option value="<?php echo $page->ID; ?>" <?php echo (($fp_settings['general_settings']['page_links']['welcome'] == $page->ID) ? 'selected' : '') ?>><?php echo $page->post_name; ?></option>
										<?php 
									} 
								} 
							?>
                        </select>
                    </td>
                </tr>
            </table>
            <input type="submit" value="submit"> 
        </form>
    </div>
<?php }

if( (!empty(get_option('fp_settings')['general_settings']['page_links']['login']) 
		&& get_option('fp_settings')['general_settings']['page_links']['login'] != 0 
		&& get_option('fp_settings')['general_settings']['page_links']['login'] != 'Select Page' ) 
	|| (!empty(get_option('fp_settings')['general_settings']['page_links']['dashboard']) 
		&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 0  
		&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 'Select Page'))
	{

	/**
	 * redirect to another page from login.php
	 */
	if(!empty(get_option('fp_settings')['general_settings']['page_links']['login']) 
	&& get_option('fp_settings')['general_settings']['page_links']['login'] != 0 
	&& get_option('fp_settings')['general_settings']['page_links']['login'] != 'Select Page' ) {

		function fp_wpLogin_redirect( $login_url, $redirect, $force_reauth ) {
			$login_page = get_permalink(get_option('fp_settings')['general_settings']['page_links']['login']);
			$login_url = add_query_arg( '', $redirect, $login_page );
			return $login_url;
		}
		add_filter( 'login_url', 'fp_wpLogin_redirect', 10, 3 );
	}

	if(!empty(get_option('fp_settings')['general_settings']['page_links']['login']) 
	&& get_option('fp_settings')['general_settings']['page_links']['login'] != 0 
	&& get_option('fp_settings')['general_settings']['page_links']['login'] != 'Select Page' ) {
		/**
		 * redirect to another page from wp-admin
		 */
		function fp_wpAdmin_redirect() {
			if ( is_admin() && ! current_user_can( 'administrator' ) &&
				! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
				wp_redirect( get_permalink(get_option('fp_settings')['general_settings']['page_links']['login']) );
				exit;
			}
		}
		add_action( 'init', 'fp_wpAdmin_redirect' );
	}

	/**
	 * Check if user credentials are correct and 
	 * if not then keep them on the same login page
	 */
	function fusepress_valid_creds( $user, $username, $password ) {
		if ( is_wp_error( $user ) && isset( $_SERVER[ 'HTTP_REFERER' ] ) && !strpos( $_SERVER[ 'HTTP_REFERER' ], 'wp-admin' ) && !strpos( $_SERVER[ 'HTTP_REFERER' ], 'wp-login.php' ) ) {
		$referrer = $_SERVER[ 'HTTP_REFERER' ];
		foreach ( $user->errors as $key => $error ) {
			if ( in_array( $key, array( 'empty_password', 'empty_username') ) ) {
				unset( $user->errors[ $key ] );
				$user->errors[ 'custom_'.$key ] = $error;
			}
			}
		}
		return $user;
	}
	add_filter( 'authenticate', 'fusepress_valid_creds', 31, 3);

	/**
	 * Just simple function to get the current user role
	 */
	function fp_current_user_role(){
		$user = wp_get_current_user();
		$roles = ( array ) $user->roles;
		return $roles[0];
	}

	if( (!empty(get_option('fp_settings')['general_settings']['page_links']['dashboard']) 
	&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 0  
	&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 'Select Page')){
		/**
		 * After successfull redirect to the dashboard according to the user-role 
		 */
		function fp_login_redirect( $redirect_to, $request, $user ) {
			if ( is_a ( $user , 'WP_User' ) && $user->exists() ) {
				if ( $user && is_object( $user ) && is_a( $user, 'WP_User' ) ) {
					if ( $user->has_cap( 'administrator' ) ) {
						$url = get_admin_url();
					} else {
						$url = get_permalink(get_option('fp_settings')['general_settings']['page_links']['dashboard']);
					}
				}
				return $url;
			}
			return $redirect_to;
		}
		// add_filter( 'login_redirect', 'fp_login_redirect', 10, 3 ); 
	}

	/**
	 * Manage the redirection for logged in user 
	 * If they direcly hit any template-url then check the role and then allow access 
	 */
	function fp_custom_redirect(){
		if(is_page('login')){
			if ( is_user_logged_in() ) { 
				if(fp_current_user_role() == 'administrator'){
					wp_safe_redirect( get_dashboard_url() );
				}else{
					if( (!empty(get_option('fp_settings')['general_settings']['page_links']['dashboard']) 
					&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 0  
					&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 'Select Page')){
						wp_safe_redirect( get_permalink(get_option('fp_settings')['general_settings']['page_links']['dashboard']) );
					}else{
						wp_safe_redirect( get_permalink( get_option('woocommerce_myaccount_page_id') ));
					}
				}
			}
		}elseif(is_page(get_option('fp_settings')['general_settings']['page_links']['dashboard'])){
			if ( !is_user_logged_in() ) { 
				if(!empty(get_option('fp_settings')['general_settings']['page_links']['login']) 
				&& get_option('fp_settings')['general_settings']['page_links']['login'] != 0 
				&& get_option('fp_settings')['general_settings']['page_links']['login'] != 'Select Page' ) {
					wp_safe_redirect( get_permalink(get_option('fp_settings')['general_settings']['page_links']['login']) );
				}else{
					wp_safe_redirect( wp_login_url());
				}
			}
		}elseif ( ! is_admin() && ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) ) {
			if ( is_user_logged_in() ) { 
				if(fp_current_user_role() != 'administrator'){
					if( (!empty(get_option('fp_settings')['general_settings']['page_links']['dashboard']) 
					&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 0  
					&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 'Select Page')){
						wp_safe_redirect( get_permalink(get_option('fp_settings')['general_settings']['page_links']['dashboard']) );
					}else{
						wp_safe_redirect( get_permalink( get_option('woocommerce_myaccount_page_id') ));
					}
				}
			}
		}
	}
	add_action( 'template_redirect', 'fp_custom_redirect' );
}

/**
 * Custom registration screen
 */
function fp_custom_registration() {
	ob_start();
		global $wpdb;

		if ($_POST && isset($_POST['r_fname']) && isset($_POST['r_lname']) && isset($_POST['r_email']) && isset($_POST['r_pass']) && isset($_POST['r_cpass'])  ) {
			$r_fname = $wpdb->escape($_POST['r_fname']);
			$r_lname = $wpdb->escape($_POST['r_lname']);
			$r_email = $wpdb->escape($_POST['r_email']);
			$r_pass  = $wpdb->escape($_POST['r_pass']);
			$r_cpass = $wpdb->escape($_POST['r_cpass']);

			$error = array();
			if (strpos($r_fname, ' ') !== FALSE) {
				$error['username_space'] = "Username has Space";
			}
			if (empty($r_fname)) {
				$error['username_empty'] = "Needed Username must";
			}
			if (username_exists($r_fname)) {
				$error['username_exists'] = "Username already exists";
			}
			if (strpos($r_lname, ' ') !== FALSE) {
				$error['lastname_space'] = "Lastname has Space";
			}
			if (empty($r_lname)) {
				$error['lastname_empty'] = "Needed Lastname must";
			}
			if (!is_email($r_email)) {
				$error['email_valid'] = "Email has no valid value";
			}
			if (email_exists($r_email)) {
				$error['email_existence'] = "Email already exists";
			}
			if (strcmp($r_pass, $r_cpass) !== 0) {
				$error['password'] = "Password didn't match";
			}
			if (count($error) == 0) {
				$id = wp_create_user($r_fname, $r_pass, $r_email);

				if(is_wp_error($id)){
					$error['user_creation_error'] = $id->get_error_message();
				}else{
					$user = get_user_by('id', $id);
					$user->set_role( 'customer' );
					$r_pass = $user->user_pass; // Override the r_pass variable to get hash password 

					wp_remote_post('https://e189-14-102-161-146.in.ngrok.io/api/register?email='.$r_email.'&password='.$r_pass.'&fp_api_key=[%23_e1!m>Z|AJNn!s%^U@cSL1Qp$.)D{_d%23i|2-M8TsP%23<Y,XMIh>HR|1L|*<s@@');
				}

				exit();
			}else{
				if(!empty($error)){
					foreach ($error as $key => $value) {
						echo "<p class='registration_error'>" . $value . '</p>';
					}
				}
			}
		}?>

			<?php if(!empty($_GET['login'])){
				if($_GET['login'] == "fail"){
					echo "<p class='login_error'>Invalid credentials!</p>";
				}
			} ?>
			<!-- html start -->
			<div class="main_auth">
				<div class="main_auth_inner">
					<div class="home_logo">
						<a href="#">
							<img src="<?php echo get_stylesheet_directory_uri(); ?>/home_log.png">
						</a>
					</div>
					<div class="select_login_screen"><?php //_e('Login'); ?>
						<div class="login_register">
							<span>Login</span>
							<label class="switch">
								<input type="checkbox" id="select_login_screen" name="select_login_screen">
								<span class="slider round"></span>
							</label>
							<span>Register</span>
						</div>
					</div>

			
					<div class="fp_custom_login">
						<form id="wp_login_form" method="post">
							<div class="input-container">
								<i class="fa fa-user icon"></i>
								<input id="username" type="text" name="username" value="" class="input-field" placeholder="Enter user name">
							</div>
							<div class="input-container">
								<i class="fa fa-envelope icon"></i>
								<input id="email" type="text" name="email" value="" class="input-field" placeholder="Enter email">
							</div>
							<div class="input-container">
								<i class="fa fa-lock icon"></i>
								<input id="password" type="password" name="password" value="" placeholder="Password"  class="input-field">
								<i class="fa fa-eye icon icn_sec"></i>
							</div>
							<div class="forget_password">
								<a href="JavaScript:void(0)" class="fp_forgot_pass"><?php _e('Forgot Password?'); ?></a>
							</div>
							<!-- <br>
							<a href="<?php //echo site_url() . '/wp-admin/admin-ajax.php?action=github_oauth_redirect'; ?>"><?php _e('Github'); ?></a>
							<br> -->

							<input type="hidden" name="action" value="fp_custom_login_function">
							<input class="submitbtn btn" type="submit" value="Login" name="submit">
						</form>
						<p class="log_reg_with">OR Login with</p>
						<div class="social_login">
						<ul>
							<li><a href=""><i class="fab fa-google"></i></a></li>
							<li><a href=""><i class="fab fa-google-plus-g"></i></a></li>
							<li><a href=""><i class="fab fa-facebook-f"></i></a></li>
							<li><a href=""><i class="fab fa-github"></i></a></li>
						</ul>
					</div>
					</div>

					<div class="fp_custom_registration" style="display:none">
						<form method="post">
							<div class="rowc">
								<div class="col-md-6c">
									<div class="input-container">
										<i class="fa fa-user icon"></i>
										<input type="text" id="r_fname" name="r_fname" placeholder="First Name" class="input-field">
									</div>
								</div>
								<div class="col-md-6c">
									<div class="input-container">
										<i class="fa fa-user icon"></i>
										<input type="text" id="r_lname" name="r_lname" placeholder="Last Name" class="input-field">
									</div>
								</div>	
							</div>
							<div class="input-container">
								<i class="fa fa-envelope icon"></i>
								<input type="email" id="r_email" name="r_email" placeholder="Email Id/Username" class="input-field">
							</div>

							<div class="input-container">
								<i class="fa fa-lock icon"></i>
								<input type="password" id="r_pass" name="r_pass" placeholder="Password" class="input-field">
								<i class="fa fa-eye icon icn_sec"></i>
							</div>
							

							<div class="input-container">
								<i class="fa fa-lock icon"></i>
								<input type="text" id="r_cpass" name="r_cpass" placeholder="Confirm Password" class="input-field">
								<i class="fa fa-eye icon icn_sec"></i>
							</div>
							<div class="input-container">
								<input type="checkbox" id="tc" name="tc" value="tc">
  								<label for="tc" class="tc">I agree terms and condition( Lorem ipsum dolor sit amet consectetur adipiscing)</label>
							</div>
							

							<input type="submit" name="btnsubmit" class="btn" value="Register">
						</form>
							<p class="log_reg_with">OR Register with</p>
							<div class="social_login">
								<ul>
									<li><a href=""><i class="fab fa-google"></i></a></li>
									<li><a href=""><i class="fab fa-google-plus-g"></i></a></li>
									<li><a href=""><i class="fab fa-facebook-f"></i></a></li>
									<li><a href=""><i class="fab fa-github"></i></a></li>
								</ul>
						</div>
					</div>
					
				</div>
			</div>
			
			<!-- html end -->
		<?php

			if (!is_user_logged_in()) {
				global $getPasswordError, $getPasswordSuccess;

				if (!empty($getPasswordError)) {
					?>
					<div class="alert alert-danger">
						<?php echo $getPasswordError; ?>
					</div>
				<?php } ?>

				<?php if (!empty($getPasswordSuccess)) { ?>
					<br/>
					<div class="alert alert-success">
						<?php echo $getPasswordSuccess; ?>
					</div>
				<?php } ?>

				<form method="post" class="wc-forgot-pwd-form" style="display:none">
					<div class="forgot_pwd_form">
						<div class="log_user">
							<label for="user_login"><?php _e('Username or E-mail:'); ?></label>
							<?php $user_login = isset($_POST['user_login']) ? $_POST['user_login'] : ''; ?>
							<input type="text" name="user_login" id="user_login" value="<?php echo $user_login; ?>" />
						</div>
						<div class="log_user">
							<?php
							ob_start();
							do_action('lostpassword_form');
							echo ob_get_clean();
							?>
							<?php wp_nonce_field('userGetPassword', 'formType'); ?>
							<button type="submit" class="get_new_password"><?php _e('Get New Password'); ?></button>
						</div>
					</div>
				</form>

				<?php
			}
		
		$output = ob_get_clean();
		echo $output;
}
add_shortcode( 'fp_custom_registration', 'fp_custom_registration' );


/**
* Custom login process
*/ 
add_action( 'wp_ajax_nopriv_fp_custom_login_function', 'fp_custom_login_function' );
add_action( 'wp_ajax_fp_custom_login_function', 'fp_custom_login_function' );
function fp_custom_login_function(){
	$fp_login_response = array();		

	if(!empty($_POST['username']) && !empty($_POST['password'])){
		$login_user_name = $_POST['username'];
		$login_user_pass = $_POST['password'];

		$creds = array(
			'user_login'    => $login_user_name,
			'user_password' => $login_user_pass,
			'remember'      => true
		);

		$user = wp_signon( $creds, false );

		if ( is_wp_error( $user ) ) {
			$fp_login_response['loginStatus'] = "logInFail";
			$fp_login_response['message'] = strip_tags($user->get_error_message());
			$fp_login_response['redirect'] = "true";

			$referrer = $_SERVER['HTTP_REFERER']; 
			if ( !empty( $referrer ) && !strstr( $referrer,'wp-login' ) && !strstr( $referrer,'wp-admin' ) ) {
				$referrer = esc_url( remove_query_arg( 'login', $referrer ) );
				$fp_login_response['redirectUrl'] = $referrer . '?login=fail';
			}
		}else{
			// Essentials for successful custom login redirection
			$secure_cookie = is_ssl();
			$secure_cookie = apply_filters('secure_signon_cookie', $secure_cookie, $creds);
			$user_loggedin = wp_authenticate($creds['user_login'], $creds['user_password']);
			wp_set_auth_cookie($user_loggedin->ID, $creds["remember"], $secure_cookie);

			$fp_user_meta = get_userdata($user->ID);
			$fp_user_role = $fp_user_meta->roles[0];
			$login_user_email = $fp_user_meta->user_email;
			$login_user_encrypted_pass = get_userdata($user->ID)->user_pass;

			// Save the data to the laravel db
			$token_request = wp_remote_post('https://e189-14-102-161-146.in.ngrok.io/api/login?email='.$login_user_email.'&password='.$login_user_encrypted_pass.'&fp_api_key=[%23_e1!m>Z|AJNn!s%^U@cSL1Qp$.)D{_d%23i|2-M8TsP%23<Y,XMIh>HR|1L|*<s@@');

			if( is_wp_error( $token_request ) ) {
				echo "The token is not generated, register first or check the password!";
			}else{
				$login_body = wp_remote_retrieve_body( $token_request );
				$login_response = json_decode($login_body);

				// Check for error
				if ( is_wp_error( $login_body ) || !isset($login_response) ) {
					echo "API is not working";	
					wp_destroy_current_session();
					wp_clear_auth_cookie();
					wp_set_current_user( 0 );
				}else{
					if( !empty( $login_response->access_token ) ) {
						$fp_login_response['loginStatus'] = "loggedIn";
						$fp_login_response['message'] = "Login successful, redirecting...";
						$fp_login_response['redirect'] = "true";
						update_user_meta( $user->ID, 'login_token', $login_response->access_token );
						
						if($fp_user_role == 'administrator'){
							$fp_login_response['redirectUrl'] = get_dashboard_url();
						}else{
							if( (!empty(get_option('fp_settings')['general_settings']['page_links']['dashboard']) 
							&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 0  
							&& get_option('fp_settings')['general_settings']['page_links']['dashboard'] != 'Select Page')){
								$fp_login_response['redirectUrl'] = get_permalink(get_option('fp_settings')['general_settings']['page_links']['dashboard']);
							}else{
								$fp_login_response['redirectUrl'] = get_permalink( get_option('woocommerce_myaccount_page_id') );
							}	
						}
					}else{
						echo "token is Rejected from the laravel";
					}
				}
			}
		}
		wp_send_json($fp_login_response);
	}else{
		$fp_login_response['loginStatus'] = "The credentials are not filled";
		wp_send_json($fp_login_response);
	}

	exit;
}

/**
 * forgot password - Get verification mail screen
 */ 
add_action('wp', 'fp_user_forgot_pwd_callback');
function fp_user_forgot_pwd_callback() {
	if (isset($_POST['formType']) && wp_verify_nonce($_POST['formType'], 'userGetPassword')) {
		global $getPasswordError, $getPasswordSuccess;
		$email = trim($_POST['user_login']);

		if (empty($email)) {
			$getPasswordError = '<strong>Error! </strong>Enter a e-mail address.';
		} else if (!is_email($email)) {
			$getPasswordError = '<strong>Error! </strong>Invalid e-mail address.';
		} else if (!email_exists($email)) {
			$getPasswordError = '<strong>Error! </strong>There is no user registered with that email address.';
		} else {
			// if  update user return true then lets send user an email containing the new password
			$hash = md5(current_datetime()->format('Y-m-d H:i:s'));
			$hash_expiry = strtotime(current_datetime()->format('Y-m-d H:i:s'));
			$hash_expiry_validate = strtotime(current_datetime()->format('Y-m-d H:i:s') . "+72hours");
			$reset_user = get_user_by( 'email', $email );
			$reset_userId = $reset_user->ID;
			update_user_meta( $reset_userId, 'reset_token', $hash );
			update_user_meta( $reset_userId, 'token_valid_time', $hash_expiry_validate );

			$to = $email;
			$subject = 'Password Reset';
			$sender = get_bloginfo('name');

			$message  = 'Someone has requested a password reset for the following account:';
			$message .= '<br><br>';
			$message .= 'Site Name: ' . get_bloginfo('name');
			$message .= '<br>';
			$message .= 'User: ' . $email;
			$message .= '<br><br>';
			$message .= 'If this was a mistake, ignore this email and nothing will happen.';
			$message .= '<br><br>';
			$message .= 'To reset your password, visit the following address: ';
			$message .= '<br><br>';
			$message .= '</a href="https://fusepress.test/reset-password/?id=' . $reset_userId . '&token=' . $hash . '&valid='.$hash_expiry.'">https://fusepress.test/reset-password/?id=' . $reset_userId . '&token=' . $hash . '&valid='. $hash_expiry .'</a>';
			
			$headers = array('Content-Type: text/html; charset=UTF-8');

			$mail = wp_mail($to, $subject, $message, $headers);
			if ($mail) {
				$getPasswordSuccess = '<strong>Success!</strong> Check your email address to reset password.';
			}else{
				$getPasswordError = 'The server is busy, please try after sometime!';
			}			
		}
	}
}

/**
 * forgot password - Add user mail to change the password
 */ 
add_shortcode('fp_reset_pass', 'fp_reset_pass_callback');
function fp_reset_pass_callback() {
	ob_start();
	if (!is_user_logged_in()) {
		if(isset($_GET['token']) && isset($_GET['id'])){
			if(!empty($_GET['token']) && !empty($_GET['id'])){
				global $resetPasswordError, $resetPasswordSuccess;

				if (!empty($resetPasswordError)) { ?>
					<div class="alert alert-danger"><?php echo $resetPasswordError; ?> </div>
				<?php } ?>
		
				<?php if (!empty($resetPasswordSuccess)) { ?>
					<br/> <div class="alert alert-success"> <?php echo $resetPasswordSuccess; ?> </div>
				<?php } ?>
		
				<form method="post" class="fp-reset-pwd">
					<div class="reset_pwd_form">
						<div class="reset_user">
							<label for="fp_user_pass">Enter new password:</label>
							<?php $fp_user_pass = isset($_POST['fp_user_pass']) ? $_POST['fp_user_pass'] : ''; ?>
							<input type="text" name="fp_user_pass" id="fp_user_pass" value="<?php echo $fp_user_pass; ?>" />
						</div>
						<div class="reset_user">
							<?php wp_nonce_field('userResetPassword', 'formType1'); ?>
							<button type="submit" class="get_new_password">Get New Password</button>
						</div>
					</div>
				</form>
				
				<?php
			}
		}else{
			echo "Unauthorized page";
		}
	}else{
		echo "Unauthorized page";
	}

	$reset_pwd_form = ob_get_clean();
	echo $reset_pwd_form;
}

/**
 * forgot password - change the password screen
 */ 
add_action('wp', 'fp_reset_pass');
function fp_reset_pass() {
	if (isset($_POST['formType1']) && wp_verify_nonce($_POST['formType1'], 'userResetPassword')) {
		global $resetPasswordError, $resetPasswordSuccess;
		$newPass = trim($_POST['fp_user_pass']);

		if(isset($_GET['id']) && isset($_GET['token']) && isset($_GET['valid']) ){
			$reset_user_id 			= $_GET['id'];
			$reset_user_token 		= $_GET['token'];
			$reset_user_token_valid = $_GET['valid'];
			if(!empty($reset_user_token)){
				$checkToken = get_user_meta( $reset_user_id, 'reset_token', true);
				$checkExpiry = get_user_meta( $reset_user_id, 'token_valid_time', true);

				if($reset_user_token_valid < $checkExpiry){
					if($reset_user_token == $checkToken){
						$update_user = wp_update_user(array(
							'ID' => $reset_user_id,
							'user_pass' => $newPass
							)
						);
						delete_user_meta( $reset_user_id, 'reset_token' );
						delete_user_meta( $reset_user_id, 'token_valid_time' );
						$resetPasswordSuccess = "Password is changed";
					}else{
						$resetPasswordError = "Please try to generate new link, your token is expired.";
					}
				}else{
					$resetPasswordError = "Please try to generate new link, your token is expired.";
				}
			}
		}
	}
}
?>