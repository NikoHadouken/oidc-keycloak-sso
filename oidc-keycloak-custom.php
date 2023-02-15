<?php

/**
 * Plugin Name: OpenID Connect Client Customizations
 * Description: Provides customizations for the OpenID Connect Client plugin.
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
		$res = Requests::request("{$this->base_url}/{$endpoint}", [
			...$headers,
			'Authorization' => "Bearer {$this->get_token()}",
		], $data, $method);

		return $res;
	}

	private function get_token()
	{
		$token = get_transient(self::TOKEN_TRANSIENT_KEY);

		if ($token) {
			return $token;
		}

		$res = Requests::post("{$this->base_url}/realms/{$this->realm}/protocol/openid-connect/token", [
			'content-type' => 'application/x-www-form-urlencoded',
		], [
			'grant_type' => 'client_credentials',
			'client_id' => urlencode($this->client_id),
			'client_secret' => urlencode($this->client_secret),
		]);

		if ($res->status_code >= 400 && $res->status_code <= 600) {
			throw new \RuntimeException('failed to get access token');
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
		};

		if ($username) {
			$params['username'] = $username;
		}

		if ($exact) {
			$params['exact'] = 'true';
		}

		$res = $this->request('GET', "admin/realms/{$this->realm}/users", $params);

		if ($res->status_code >= 400 && $res->status_code <= 600) {
			throw new \RuntimeException('find users failed');
		}

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

		if ($firstName) {
			$user['firstName'] = $firstName;
		}

		if ($lastName) {
			$user['lastName'] = $lastName;
		}

		$res = $this->request('POST', "admin/realms/{$this->realm}/users", json_encode($user), [
			'Content-Type' => 'application/json',
		]);

		if ($res->status_code >= 400 && $res->status_code <= 600) {
			throw new \RuntimeException('create user failed');
		}
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

	$email_exists = function (string $email) use ($keycloak) {
		if (!$keycloak) {
			return email_exists($email);
		}
		try {
			return !!$keycloak->find_user(email: $email, exact: true);
		} catch (\Throwable $e) {
			error_log('wc_create_new_customer: find user by email failed: ' . $e->getMessage());
			return email_exists($email);
		}
	};

	$username_exists = function (string $username) use ($keycloak) {
		if (!$keycloak) {
			return username_exists($username);
		}
		try {
			return !!$keycloak->find_user(username: $username, exact: true);
		} catch (\Throwable $e) {
			error_log('wc_create_new_customer: find user by username failed: ' . $e->getMessage());
			return username_exists($username);
		}
	};

	$create_user = function (array $new_customer_data) use ($keycloak) {
		if ($keycloak) {
			try {
				$keycloak->create_user(
					username: $new_customer_data['user_login'],
					email: $new_customer_data['user_email'],
					password: $new_customer_data['user_pass'],
					firstName: $new_customer_data['first_name'],
					lastName: $new_customer_data['last_name'],
				);
			} catch (\Throwable $e) {
				error_log('wc_create_new_customer: create user failed: ' . $e->getMessage());
			}
		}

		$customer_id = wp_insert_user($new_customer_data);

		if ($keycloak && class_exists('OpenID_Connect_Generic')) {
			try {
				$user = $keycloak->find_user(email: $new_customer_data['user_email'], exact: true);
			} catch (\Throwable $e) {
				$user = null;
				error_log('wc_create_new_customer: find new user failed: ' . $e->getMessage());
			}

			if ($user) {
				$client_wrapper = OpenID_Connect_Generic::instance()->client_wrapper;
				$client_wrapper->update_existing_user($customer_id, $user['id']);
			}
		}

		return $customer_id;
	};

	if (empty($email) || !is_email($email)) {
		return new WP_Error('registration-error-invalid-email', __('Please provide a valid email address.', 'woocommerce'));
	}

	if ($email_exists($email)) {
		return new WP_Error('registration-error-email-exists', apply_filters('woocommerce_registration_error_email_exists', __('An account is already registered with your email address. <a href="#" class="showlogin">Please log in.</a>', 'woocommerce'), $email));
	}

	if ('yes' === get_option('woocommerce_registration_generate_username', 'yes') && empty($username)) {
		$username = wc_create_new_customer_username($email, $args);
	}

	$username = sanitize_user($username);

	if (empty($username) || !validate_username($username)) {
		return new WP_Error('registration-error-invalid-username', __('Please enter a valid account username.', 'woocommerce'));
	}

	if ($username_exists($username)) {
		return new WP_Error('registration-error-username-exists', __('An account is already registered with that username. Please choose another.', 'woocommerce'));
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
