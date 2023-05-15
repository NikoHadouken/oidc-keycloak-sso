<?php

/**
 * Plugin Name: OpenID Connect Client Customizations
 * Description: Provides customizations for the OpenID Connect Client plugin.
 *
 * Features:
 *  - Customize Login Button Text
 *  - Require IdP role for user creation
 *  - Role mapping from IdP to wordpress roles
 * 		- roles are mapped on user creation and login
 *  - Set default wordpress role when user has no roles mapped
 *
 *  - keycloak api client
 *  - create keycloak user in woocommerce checkout
 *  - prevent updating user email, firstName, lastName on My Account page
 *  - wp user bulk action to create missing wordpress users in keycloak
 *  - show keycloak user id in user profile (admin)
 *  - show keycloak user id in user table column
 *  - find users via keycloak user id (subject identity) in rest api
 *  - overwrite login_type to button via query param
 *
 * @package  OpenidConnectGeneric_MuPlugin
 *
 * @link     https://github.com/daggerhart/openid-connect-generic
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
	die;
}



function oidc_keycloak_get_user_roles($user_claims, $client_id = null)
{
	$roles = [];
	if (isset($user_claims['realm_access']['roles'])) {
		array_push($roles, ...$user_claims['realm_access']['roles']);
	}
	if ($client_id && isset($user_claims['resource_access'][$client_id]['roles'])) {
		array_push($roles, ...$user_claims['resource_access'][$client_id]['roles']);
	}
	return $roles;
}

/**
 * Modifies the OIDC login button text.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-login-button-text
 *
 * @param string $text The button text.
 *
 * @return string
 */
function oidc_keycloak_login_button_text($text)
{
	/** @var mixed[] */
	$settings = get_option('openid_connect_generic_settings', array());

	$text = (!empty($settings['oidc_login_button_text'])) ? strval($settings['oidc_login_button_text']) : __('Login with Keycloak', 'oidc-keycloak-mu-plugin');

	return $text;
}
add_filter('openid-connect-generic-login-button-text', 'oidc_keycloak_login_button_text', 10, 1);

/**
 * Adds a new setting that allows an Administrator to set the button text from
 * the plugin settings screen.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-settings-fields
 *
 * @param array<mixed> $fields The array of settings fields.
 *
 * @return array<mixed>
 */
function oidc_keycloak_add_login_button_text_setting($fields)
{

	// @var array<mixed> $field_array
	$field_array = array(
		'oidc_login_button_text' => array(
			'title'       => __('Login Button Text', 'oidc-keycloak-mu-plugin'),
			'description' => __('Set the login button label text.', 'oidc-keycloak-mu-plugin'),
			'type'        => 'text',
			'section'     => 'client_settings',
		),
	);

	// Prepend the field array with the new field to push it to the top of the settings screen.
	return $field_array + $fields;
}
add_filter('openid-connect-generic-settings-fields', 'oidc_keycloak_add_login_button_text_setting', 10, 1);

/**
 * Setting to indicate whether an IDP role mapping is required for user creation.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-settings-fields
 *
 * @param array<mixed> $fields The array of settings fields.
 *
 * @return array<mixed>
 */
function oidc_keycloak_add_require_idp_role_setting($fields)
{

	$fields['require_idp_user_role'] = array(
		'title'       => __('Valid IDP User Role Required', 'oidc-keycloak-mu-plugin'),
		'description' => __('When enabled, this will prevent users from being created if they don\'t have a valid mapped IDP to WordPress role.', 'oidc-keycloak-mu-plugin'),
		'type'        => 'checkbox',
		'section'     => 'user_settings',
	);

	return $fields;
}
add_filter('openid-connect-generic-settings-fields', 'oidc_keycloak_add_require_idp_role_setting', 10, 1);

/**
 * Adds a new setting that allows configuration of the default role assigned
 * to users when no IDP role is provided.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-settings-fields
 *
 * @param array<mixed> $fields The array of settings fields.
 *
 * @return array<mixed>
 */
function oidc_keycloak_add_default_role_setting($fields)
{

	/** @var WP_Roles */
	$wp_roles_obj = wp_roles();

	/** @var string[] */
	$roles = $wp_roles_obj->get_names();

	// Prepend a blank role as the default.
	array_unshift($roles, '-- None --');

	// Setting to specify default user role when no role is provided by the IDP.
	$fields['default_user_role'] = array(
		'title'       => __('Default New User Role', 'oidc-keycloak-mu-plugin'),
		'description' => __('Set the default role assigned to users when the IDP doesn\'t provide a role.', 'oidc-keycloak-mu-plugin'),
		'type'        => 'select',
		'options'     => $roles,
		'section'     => 'user_settings',
	);

	return $fields;
}
add_filter('openid-connect-generic-settings-fields', 'oidc_keycloak_add_default_role_setting', 10, 1);

/**
 * Adds new settings that allows mapping IDP roles to WordPress roles.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-settings-fields
 *
 * @param array<mixed> $fields The array of settings fields.
 *
 * @return array<mixed>
 */
function oidc_keycloak_role_mapping_setting($fields)
{

	/** @var WP_Roles $wp_roles_obj */
	$wp_roles_obj = wp_roles();

	/** @var string[]  */
	$roles = $wp_roles_obj->get_names();

	foreach ($roles as $role) {
		$fields['oidc_idp_' . strtolower($role) . '_roles'] = array(
			'title'       => sprintf(__('IDP Role for WordPress %ss', 'oidc-keycloak-mu-plugin'), $role),
			'description' => sprintf(
				__('Semi-colon(;) separated list of IDP roles to map to the %s WordPress role', 'oidc-keycloak-mu-plugin'),
				$role
			),
			'type'        => 'text',
			'section'     => 'user_settings',
		);
	}

	return $fields;
}
add_filter('openid-connect-generic-settings-fields', 'oidc_keycloak_role_mapping_setting', 10, 1);

/**
 * Determine whether user should be created using plugin settings & IDP identity.
 *
 * @param bool         $result     The plugin user creation test flag.
 * @param array<mixed> $user_claim The authenticated user's IDP Identity Token user claim.
 *
 * @return bool
 */
function oidc_keycloak_user_creation_test($result, $user_claim)
{

	/** @var mixed[] */
	$settings = get_option('openid_connect_generic_settings', array());

	// If the custom IDP role requirement setting is enabled validate user claim.
	if (!empty($settings['require_idp_user_role']) && boolval($settings['require_idp_user_role'])) {
		// The default is to not create an account unless a mapping is found.
		$result = false;

		/** @var WP_Roles */
		$wp_roles_obj = wp_roles();

		/** @var string[] */
		$roles = $wp_roles_obj->get_names();

		// Check the user claim for idp roles to lookup the WordPress role mapping.
		$idp_roles = oidc_keycloak_get_user_roles($user_claim, $settings['client_id']);
		if (!empty($settings)) {
			foreach ($idp_roles as $idp_role) {
				foreach ($roles as $role_id => $role_name) {
					if (!empty($settings['oidc_idp_' . strtolower($role_name) . '_roles'])) {
						if (in_array($idp_role, explode(';', $settings['oidc_idp_' . strtolower($role_name) . '_roles']))) {
							$result = true;
						}
					}
				}
			}
		}
	}

	return $result;
}
add_filter('openid-connect-generic-user-creation-test', 'oidc_keycloak_user_creation_test', 10, 2);

/**
 * Set user role on based on IDP role after authentication.
 *
 * @param WP_User      $user       The authenticated user's WP_User object.
 * @param array<mixed> $user_claim The IDP provided Identity Token user claim array.
 *
 * @return void
 */
function oidc_keycloak_map_user_role($user, $user_claim)
{
	/** @var WP_Roles */
	$wp_roles_obj = wp_roles();

	/** @var string[]  */
	$roles = $wp_roles_obj->get_names();

	/** @var mixed[] */
	$settings = get_option('openid_connect_generic_settings', array());

	// Check the user claim for idp roles to lookup the WordPress role for mapping.
	$idp_roles = oidc_keycloak_get_user_roles($user_claim, $settings['client_id']);
	if (!empty($settings)) {
		$role_count = 0;

		foreach ($roles as $role_id => $role_name) {
			// skip non-configurable roles
			if (empty($settings['oidc_idp_' . strtolower($role_name) . '_roles'])) {
				continue;
			}
			// idp roles for current wordpress role
			$role_mappings = explode(';', $settings['oidc_idp_' . strtolower($role_name) . '_roles']);
			if (array_intersect($idp_roles, $role_mappings)) {
				$user->add_role($role_id);
				$role_count++;
			} else {
				$user->remove_role($role_id);
			}
		}

		if (intval($role_count) == 0 && !empty($settings['default_user_role'])) {
			if (boolval($settings['default_user_role'])) {
				$user->set_role($settings['default_user_role']);
			}
		}
	}
}
add_action('openid-connect-generic-update-user-using-current-claim', 'oidc_keycloak_map_user_role', 10, 2);
add_action('openid-connect-generic-user-create', 'oidc_keycloak_map_user_role', 10, 2);


/**
 * Adds a section for configuring a Keycloak API client to the settings page.
 */
function oidc_keycloak_add_settings_section()
{
	add_settings_section(
		'keycloak_api_settings',
		__('Keycloak API Settings', 'oidc-keycloak-mu-plugin'),
		function () {
			esc_html_e('Enter settings for a Keycloak client used for m2m requests.', 'oidc-keycloak-mu-plugin');
		},
		'openid-connect-generic-settings',
	);
}
add_action('admin_init', 'oidc_keycloak_add_settings_section', 15);


/**
 *
 * Adds new settings to configure api client credentials.
 *
 * @link https://github.com/daggerhart/openid-connect-generic#openid-connect-generic-settings-fields
 *
 * @param array<mixed> $fields The array of settings fields.
 *
 * @return array<mixed>
 */
function oidc_keycloak_add_api_credentials_setting($fields)
{

	$fields['keycloak_base_url'] = array(
		'title'       => __('Base URL', 'oidc-keycloak-mu-plugin'),
		'description' => __('Should point to your Keycloak instance without the realm eg https://keycloak.example.com', 'oidc-keycloak-mu-plugin'),
		'type'        => 'text',
		'section'     => 'keycloak_api_settings',
	);

	$fields['keycloak_realm'] = array(
		'title'       => __('Realm Name', 'oidc-keycloak-mu-plugin'),
		'description' => __('Set the Keycloak realm name', 'oidc-keycloak-mu-plugin'),
		'type'        => 'text',
		'section'     => 'keycloak_api_settings',
	);

	$fields['keycloak_api_client_id'] = array(
		'title'       => __('Client ID', 'oidc-keycloak-mu-plugin'),
		'description' => __('Set the client id', 'oidc-keycloak-mu-plugin'),
		'type'        => 'text',
		'section'     => 'keycloak_api_settings',
	);

	$fields['keycloak_api_client_secret'] = array(
		'title'       => __('Client Secret', 'oidc-keycloak-mu-plugin'),
		'description' => __('Set the client secret', 'oidc-keycloak-mu-plugin'),
		'type'        => 'password',
		'section'     => 'keycloak_api_settings',
	);

	return $fields;
}
add_filter('openid-connect-generic-settings-fields', 'oidc_keycloak_add_api_credentials_setting', 10, 1);

class OIDC_KeycloakClientException extends \Exception
{
	public \WpOrg\REquests\Response $res;

	public function __construct(string $message, \WpOrg\REquests\Response $res)
	{
		$this->res = $res;
		parent::__construct($message);
	}
}

class OIDC_Keycloak_Client
{
	private string $base_url;

	private const TOKEN_TRANSIENT_KEY = 'keycloak_token';

	public function __construct(
		string $base_url,
		private string $realm,
		private string $client_id,
		private string $client_secret,
	) {
		$this->base_url = trim($base_url, '/');
	}

	public function request(
		string $method,
		string $endpoint,
		$data = [],
		array $headers = [],
	) {
		$res = \WpOrg\Requests\Requests::request("{$this->base_url}/{$endpoint}", [
			...$headers,
			'Authorization' => "Bearer {$this->get_token()}",
		], $data, $method);

		if ($res->status_code >= 400 && $res->status_code <= 600) {
			throw new OIDC_KeycloakClientException("request {$method} {$endpoint} failed", $res);
		}

		return $res;
	}

	private function get_token()
	{
		delete_transient(self::TOKEN_TRANSIENT_KEY);
		$token = get_transient(self::TOKEN_TRANSIENT_KEY);

		if ($token) {
			return $token;
		}

		$res = \WpOrg\Requests\Requests::post("{$this->base_url}/realms/{$this->realm}/protocol/openid-connect/token", [
			'content-type' => 'application/x-www-form-urlencoded',
		], [
			'grant_type' => 'client_credentials',
			'client_id' => urlencode($this->client_id),
			'client_secret' => urlencode($this->client_secret),
		]);

		if ($res->status_code >= 400 && $res->status_code <= 600) {
			throw new OIDC_KeycloakClientException('failed to get access token', $res);
		}

		[
			'access_token' => $access_token,
			'expires_in' => $expires_in, // time in seconds
		] = json_decode($res->body, true);


		// substract a couple of seconds from token expiration time
		// to prevent requests resulting in 401 Unauthorized
		set_transient(self::TOKEN_TRANSIENT_KEY, $access_token, $expires_in - 10);

		return $access_token;
	}

	public function find_users(string $email = '', string $username = '', bool $exact = false)
	{
		$params = [];

		if ($email) {
			$params['email'] = $email;
		}

		if ($username) {
			$params['username'] = $username;
		}

		if ($exact) {
			$params['exact'] = 'true';
		}

		$res = $this->request('GET', "admin/realms/{$this->realm}/users", $params);

		return json_decode($res->body, true);
	}


	public function find_user(...$args)
	{
		$user = current($this->find_users(...$args));
		return $user ? $user : null;
	}


	public function create_user(
		string $username,
		string $email,
		string $firstName = '',
		string $lastName = '',
		string $password = '',
		string $passwordHash = '',
	) {
		$user = [
			'enabled' => true,
			'username' => $username,
			'email' => $email,
		];

		if ($password) {
			$user['credentials'] = [
				[
					'type' => 'password',
					'value' => $password,
					'temporary' => false,
				],
			];
		}

		if ($passwordHash) {
			$user['credentials'] = [
				[
					'type' => 'password',
					'secretData' => json_encode([
						'value' => $passwordHash,
						"salt" => "",
						"additionalParameters" => new stdClass(),
					]),
					'credentialData' => '{"hashIterations":8,"algorithm":"phpass","additionalParameters":{}}',
					'temporary' => false,
				],
			];
		}

		if ($firstName) {
			$user['firstName'] = $firstName;
		}

		if ($lastName) {
			$user['lastName'] = $lastName;
		}

		$this->request('POST', "admin/realms/{$this->realm}/users", json_encode($user), [
			'Content-Type' => 'application/json',
		]);
	}

	public function update_user(
		string $userId,
		string $firstName = '',
		string $lastName = '',
	) {
		$user = [
			'enabled' => true,
		];

		if ($firstName) {
			$user['firstName'] = $firstName;
		}

		if ($lastName) {
			$user['lastName'] = $lastName;
		}

		$this->request('PUT', "admin/realms/{$this->realm}/users/{$userId}", json_encode($user), [
			'Content-Type' => 'application/json',
		]);
	}
}


function oidc_keycloak_get_client()
{
	/** @var mixed[] */
	$settings = get_option('openid_connect_generic_settings', array());

	// client is configured if all setting keys are set and truthy
	$configured = !array_diff(
		[
			'keycloak_base_url',
			'keycloak_realm',
			'keycloak_api_client_id',
			'keycloak_api_client_secret',
		],
		array_keys(array_filter($settings))
	);

	if (!$configured) {
		return null;
	}

	return new OIDC_Keycloak_Client(
		base_url: $settings['keycloak_base_url'],
		realm: $settings['keycloak_realm'],
		client_id: $settings['keycloak_api_client_id'],
		client_secret: $settings['keycloak_api_client_secret'],
	);
}


function oidc_keycloak_get_password_policy_violations(string $password, string $email, string $username)
{
	$violations = [];
	if (strlen($password) < 8) {
		$violations[] = [
			'policy' => 'min_length',
			'message' => __('Passwort muss mindestens 8 Zeichen lang sein', 'storl'),
		];
	}
	if (str_contains($password, $email)) {
		$violations[] = [
			'policy' => 'not_email',
			'message' => __('Passwort darf nicht die email enthalten', 'storl'),
		];
	}
	if (str_contains($password, $username)) {
		$violations[] = [
			'policy' => 'not_username',
			'message' => __('Passwort darf nicht den Username enthalten', 'storl'),
		];
	}
	if (!preg_match('/\d/', $password)) {
		$violations[] = [
			'policy' => 'digits',
			'message' => __('Passwort muss mindestens eine Ziffer enthalten', 'storl'),
		];
	}
	if (!preg_match('/[A-Z]/', $password)) {
		$violations[] = [
			'policy' => 'uppercase_characters',
			'message' => __('Passwort muss mindestens einen Großbuchtaben enthalten enthalten', 'storl'),
		];
	}
	return $violations;
}


/**
 * Monkey patch woocommerce function used on checkout to create keycloak user via api request.
 *
 * Create a new customer.
 *
 * @param  string $email    Customer email.
 * @param  string $username Customer username.
 * @param  string $password Customer password.
 * @param  array  $args     List of arguments to pass to `wp_insert_user()`.
 * @return int|WP_Error Returns WP_Error on failure, Int (user ID) on success.
 */
function wc_create_new_customer($email, $username = '', $password = '', $args = array())
{
	$keycloak = oidc_keycloak_get_client();

	if (!$keycloak) {
		return new \WP_Error('create_kc_user_failed', 'Benutzerkonto konnte nicht angelegt werden');
	}


	$create_user = function (array $new_customer_data) use ($keycloak) {
		if (!$keycloak) {
			return wp_insert_user($new_customer_data);
		}

		// keycloak user did not exist but wp user is somehow present
		// user needs to verify email
		$user = get_user_by('email', $new_customer_data['user_email']);

		if ($user) {
			return new \WP_Error('create_kc_user_failed', "WP User already exists");
			// $user->user_login = $new_customer_data['user_login'];
			$user->user_pass = $new_customer_data['user_pass'];
			$customer_id = wp_update_user($user);
		}

		$kc_user = null;
		try {
			$keycloak->create_user(
				username: $new_customer_data['user_login'],
				email: $new_customer_data['user_email'],
				password: $new_customer_data['user_pass'],
				firstName: $new_customer_data['first_name'],
				lastName: $new_customer_data['last_name'],
			);
		} catch (\Throwable $e) {
			$message = $e->getMessage();
			error_log('wc_create_new_customer: create keycloak user failed: ' . $e->getMessage());
			if ($e instanceof OIDC_KeycloakClientException) {
				error_log($e->res->status_code);
				error_log($e->res->body);

				try {
					[
						'errorMessage' => $errorMessage,
					] = json_decode($e->res->body, true);
					$message = $errorMessage;
				} catch (\Throwable $e) {
					// ignore
				}
			}
			return new \WP_Error('create_kc_user_failed', $message);
		}

		$customer_id = wp_insert_user($new_customer_data);

		if (is_wp_error($customer_id)) {
			return $customer_id;
		}


		// link keycloak uuid to user via daggerhart plugin
		if (class_exists('OpenID_Connect_Generic')) {
			$kc_user = null;
			try {
				$kc_user = $keycloak->find_user(email: $new_customer_data['user_email'], exact: true);
			} catch (\Throwable $e) {
				error_log('wc_create_new_customer: find new user failed: ' . $e->getMessage());
				if ($e instanceof OIDC_KeycloakClientException) {
					error_log($e->res->status_code);
					error_log($e->res->body);
				}
			}

			if ($kc_user) {
				$client_wrapper = OpenID_Connect_Generic::instance()->client_wrapper;
				$client_wrapper->update_existing_user($customer_id, $kc_user['id']);
			}
		}

		return $customer_id;
	};

	if (empty($email) || !is_email($email)) {
		return new WP_Error('registration-error-invalid-email', __('Please provide a valid email address.', 'woocommerce'));
	}

	try {
		$email_exists = $keycloak ? !!$keycloak->find_user(email: $email, exact: true) : email_exists($email);
		if ($email_exists) {
			return new WP_Error('registration-error-email-exists', apply_filters('woocommerce_registration_error_email_exists', __('Für diese Email Adresse existiert bereits ein Kundenkonto. <a href="/login">Bitte melde dich an.</a>', 'storl'), $email));
		}
	} catch (OIDC_KeycloakClientException $e) {
		return new WP_Error('registration-error-keycloak', $e->getMessage());
	}


	if ('yes' === get_option('woocommerce_registration_generate_username', 'yes') && empty($username)) {
		$username = wc_create_new_customer_username($email, $args);
	}

	$username = sanitize_user($username);

	if (empty($username) || !validate_username($username)) {
		return new WP_Error('registration-error-invalid-username', __('Please enter a valid account username.', 'woocommerce'));
	}

	// check existing username
	try {
		// username may not be taken in keycloak or wordpress
		$username_exists = $keycloak ? !!$keycloak->find_user(username: $username, exact: true) : username_exists($username);
		if ($username_exists) {
			return new WP_Error('registration-error-username-exists', __('An account is already registered with that username. Please choose another.', 'woocommerce'));
		}
	} catch (OIDC_KeycloakClientException $e) {
		return new WP_Error('registration-error-keycloak', $e->getMessage());
	}

	// Handle password creation.
	$password_generated = false;
	if ('yes' === get_option('woocommerce_registration_generate_password') && empty($password)) {
		$password           = wp_generate_password();
		$password_generated = true;
	}

	if (empty($password)) {
		return new WP_Error('registration-error-missing-password', __('Please enter an account password.', 'woocommerce'));
	}

	$violations = oidc_keycloak_get_password_policy_violations($password, $email, $username);
	if ($violations) {
		return new WP_Error('registration-error-invalid-password', current($violations)['message']);
	}

	// Use WP_Error to handle registration errors.
	$errors = new WP_Error();

	do_action('woocommerce_register_post', $username, $email, $errors);

	$errors = apply_filters('woocommerce_registration_errors', $errors, $username, $email);

	if ($errors->get_error_code()) {
		return $errors;
	}

	$new_customer_data = apply_filters(
		'woocommerce_new_customer_data',
		array_merge(
			$args,
			array(
				'user_login' => $username,
				'user_pass'  => $password,
				'user_email' => $email,
				'role'       => 'customer',
			)
		)
	);

	$customer_id = $create_user($new_customer_data);

	if (is_wp_error($customer_id)) {
		return $customer_id;
	}

	do_action('woocommerce_created_customer', $customer_id, $new_customer_data, $password_generated);

	return $customer_id;
}

/**
 * show keycloak user id on users table
 */
function oidc_keycloak_user_table_columns($column)
{
	$column['keycloak_user_id'] = 'Keycloak User Id';
	return $column;
}
add_filter('manage_users_columns', 'oidc_keycloak_user_table_columns');

function oidc_keycloak_output_keycloak_userid_column($val, $column_name, $user_id)
{
	if ($column_name === 'keycloak_user_id') {
		return $user_id = get_user_meta($user_id, 'openid-connect-generic-subject-identity', true);
	}
	return $val;
}
add_filter('manage_users_custom_column', 'oidc_keycloak_output_keycloak_userid_column', 10, 3);


/**
 * show keycloak user id on profile page
 */
add_action('show_user_profile', 'oidc_keycloak_display_user_id_on_user_profile', 5);
add_action('edit_user_profile', 'oidc_keycloak_display_user_id_on_user_profile', 5);
function oidc_keycloak_display_user_id_on_user_profile(WP_User $user)
{
	$user_id = get_user_meta($user->ID, 'openid-connect-generic-subject-identity', true);
?>
	<h3>Keycloak</h3>

	<table class="form-table" role="presentation">
		<tbody>
			<tr class="user-user-login-wrap">
				<th><label for="user_login">User ID</label></th>
				<td><input type="text" class="regular-text" disabled value="<?php _e($user_id) ?>" /><span class="description">User ID kann nicht geändert werden.</span></td>
			</tr>
		</tbody>
	</table>
<?php
}


function oidc_keycloak_get_wp_users_by_ids(array $user_ids)
{
	$users = get_users([
		'include' => $user_ids,
	]);

	return array_reduce($users, function ($arr, $user) {
		$arr[$user->ID] = $user;
		return $arr;
	}, $users);
}

/**
 * add bulk action to sync wordpress users to keycloak
 */
add_filter('bulk_actions-users', function (array $bulk_actions) {
	$bulk_actions['sync-to-keycloak'] = __('Sync To Keycloak', 'oidc-keycloak-mu-plugin');
	return $bulk_actions;
});


add_filter('handle_bulk_actions-users', function (string $redirect, string $action, array $user_ids) {

	if ($action !== 'sync-to-keycloak') {
		return $redirect;
	}

	$keycloak = oidc_keycloak_get_client();
	if (!$keycloak) {
		$redirect = add_query_arg(
			'kc_sync_error',
			'Keycloak client not configured.',
			$redirect,
		);
		return $redirect;
	}

	$sync_count = 0;
	$skip_count = 0;
	$errors = [];
	$addError = function ($user_id, string $error_message) use (&$errors) {
		$errors[$user_id] = $error_message;
	};

	$wp_users = oidc_keycloak_get_wp_users_by_ids($user_ids);

	foreach ($user_ids as $user_id) {
		$user = $wp_users[$user_id] ?? null;
		if (!$user) {
			$addError($user_id, 'User not found');
			continue;
		}
		$kc_user = $keycloak->find_user(email: $user->user_email, exact: true);
		if ($kc_user) {
			$skip_count++;
			continue;
		}

		try {
			$keycloak->create_user(
				username: $user->user_login,
				email: $user->user_email,
				firstName: $user->first_name,
				lastName: $user->last_name,
				passwordHash: $user->user_pass,
			);
			$sync_count++;
		} catch (\Throwable $e) {
			$addError($user_id, $e->getMessage());
		}
	}

	if ($sync_count) {
		$redirect = add_query_arg(
			'kc_synced_users',
			$sync_count,
			$redirect,
		);
	}

	if ($skip_count) {
		$redirect = add_query_arg(
			'kc_skipped_users',
			$skip_count,
			$redirect,
		);
	}

	foreach ($errors as $user_id => $error_message) {
		$redirect = add_query_arg(
			"kc_sync_user_error[{$user_id}]",
			$error_message,
			$redirect,
		);
	}

	return $redirect;
}, 10, 3);


add_action('admin_notices', function () {
	if (!empty($_REQUEST['kc_synced_users'])) {
		$synced_users = (int) $_REQUEST['kc_synced_users'];
		$message = sprintf(
			_n(
				'%d user has been synced to Keycloak.',
				'%d users have been synced to Keycloak.',
				$synced_users
			),
			$synced_users
		);

		echo "<div class=\"updated notice is-dismissible\"><p>{$message}</p></div>";
	}

	if (!empty($_REQUEST['kc_skipped_users'])) {
		$skipped_users = (int) $_REQUEST['kc_skipped_users'];
		$message = sprintf(
			_n(
				'%d user already in Keycloak.',
				'%d users already in Keycloak.',
				$skipped_users
			),
			$skipped_users
		);

		echo "<div class=\"updated notice is-dismissible\"><p>{$message}</p></div>";
	}

	if (!empty($_REQUEST['kc_sync_error'])) {
		echo "<div class=\"updated notice is-dismissible error\"><p>{$_REQUEST['update_error']}</p>";
	}

	if (!empty($_REQUEST['kc_sync_user_error']) && is_array($_REQUEST['kc_sync_user_error'])) {
		$user_ids = array_map(fn ($id) => intval($id), array_keys($_REQUEST['kc_sync_user_error']));

		$users = oidc_keycloak_get_wp_users_by_ids($user_ids);

		echo "<div class=\"updated notice is-dismissible error\"><p>Updating users failed:</p>";

		foreach ($_REQUEST['kc_sync_user_error'] as $user_id => $error_message) {
			$username = $users[$user_id]?->user_login ?? $user_id;
			$message = sprintf("%s: %s", $username, $error_message);
			echo "<p>{$message}</p>";
		}

		echo "</div>";
	}
});

add_filter('removable_query_args', function (array $removable_query_args) {
	return array_merge($removable_query_args, ['kc_sync_user_error', 'kc_skipped_users', 'kc_synced_users']);
});


/**
 * Rest API
 *
 * Find users by subject identity.
 *
 * @see wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php
 */

add_filter('rest_user_collection_params', function ($query_params) {
	$query_params['subject_identity'] = array(
		'description' => __('Limit result set to users with given subject identity (keycloak user id).'),
		'type'        => 'array',
		'items'       => array(
			'type' => 'string',
		),
		'default'     => array(),
	);

	return $query_params;
});

add_filter('rest_user_query', function ($prepared_args, $request) {
	$user_ids = $request['subject_identity'] ?? [];
	if ($user_ids) {
		$prepared_args['meta_query'] = [
			...($prepared_args['meta_query'] ?? []),
			[
				'key'     => 'openid-connect-generic-subject-identity',
				'value'   => $user_ids,
				'compare' => 'IN'
			],
		];
	}
	return $prepared_args;
}, 10, 2);


/**
 * prevent editing user details on woocommerce my account page
 * wp-content/plugins/woocommerce/includes/class-wc-form-handler.php
 */
add_action('woocommerce_save_account_details_errors', function ($errors, $user) {
	$protected_fields = [
		// 'first_name' => __('First name', 'woocommerce'),
		// 'last_name' => __('Last name', 'woocommerce'),
		'user_email' => __('Email address', 'woocommerce'),
		'user_pass' => __('Password', 'woocommerce'),
	];

	foreach ($protected_fields as $field => $label) {
		if (isset($user->$field)) {
			$errors->add("save-account-error", sprintf(__('Feld %s muss über Storl Konto geändert werden', 'storl'), $label));
		}
	}
}, 10, 2);


add_filter('woocommerce_save_account_details_required_fields', function ($required_fields) {
	$remove = [
		// 'account_first_name',
		// 'account_last_name',
		'account_email',
	];
	return array_filter($required_fields, fn ($key) => !in_array($key, $remove), ARRAY_FILTER_USE_KEY);
}, 10, 1);


/**
 * hack to show login button instead of automatic redirect based on query param
 * certian constants can be used to overwrite the settings stored in the db
 */
if (!defined('OIDC_LOGIN_TYPE') && isset($_GET['force_login_form'])) {
	define('OIDC_LOGIN_TYPE', 'button');
}

function oidc_keycloak_is_rest_api_request()
{
	if (empty($_SERVER['REQUEST_URI'])) {
		return false;
	}

	$rest_prefix         = trailingslashit(rest_get_url_prefix());
	$is_rest_api_request = (false !== strpos($_SERVER['REQUEST_URI'], $rest_prefix)); // phpcs:disable WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

	return $is_rest_api_request;
}

/**
 * store the current url to the session and use it for the redirect_to after login
 */
add_action('init', function () {
	global $wp, $pagenow;

	if (is_user_logged_in()) {
		if (isset($_COOKIE['oidc_login_redirect'])) {
			setcookie('oidc_login_redirect', '', time() - 1, COOKIEPATH, COOKIE_DOMAIN, true, true);
		}
		return;
	}

	if (!wp_using_themes() || wp_doing_ajax() || oidc_keycloak_is_rest_api_request()) {
		return;
	}

	// don't save redirect on login page
	if ('wp-login.php' == $pagenow || '/login/' === trailingslashit($_SERVER['REQUEST_URI'])) {
		return;
	}

	if (!empty($wp->did_permalink) && boolval($wp->did_permalink) === true) {
		$redirect_url = add_query_arg($_GET, trailingslashit($wp->request));
	} else {
		$redirect_url = add_query_arg(null, null);
	}

	setcookie('oidc_login_redirect', $redirect_url, time() + 1 * DAY_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, true, true);
});

add_filter('openid-connect-generic-client-redirect-to', function ($url) {

	if (isset($_COOKIE['oidc_login_redirect'])) {
		$url = home_url($_COOKIE['oidc_login_redirect']);
	}

	return $url;
});
