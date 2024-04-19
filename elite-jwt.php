<?php

/**
 * @package Elite JWT
 * /
 */

/*
Plugin Name: Elite JWT
Plugin URI: https://eliteacademyeg.com
Description: JWT for Elite Academy
Version: 1.0.0
Author: Saif Salem
Author URI: https://github.com/saifsalemm/saifsalemm
License: GPLv2 or later
Text Domain: elite-jwt
*/

if (!defined('ABSPATH')) {
    die;
}

// EliteJwt: This class handles JWT encoding and decoding

// Include required files
require __DIR__ . "/vendor/autoload.php";

// Import JWT class and Key class from EliteJWT namespace
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class EliteJwt
{
    protected $secrect;
    protected $issuer;
    protected $issuedAt;
    protected $expire;

    function __construct()
    {
        // Set default time-zone to Africa/Cairo
        date_default_timezone_set('Africa/Cairo');
        $this->issuedAt = time();

        // Define token validity (3600 seconds = 1 hour)
        $this->expire = $this->issuedAt + 3600 * 24 * 7;

        // Set a strong secret or signature for JWT
        // $this->secrect = ELITE_JWT_SECRET;

        $this->secrect = ELITE_JWT_SECRET;
        $this->issuer = ELITE_JWT_ISSUER;

        if (!$this->secrect || !$this->issuer) {
            echo '<script>alert("Elite JWT: Secret and Issuer not defined in wp-config.php");</script>';
        }

        // register actions
        add_action('rest_api_init', array($this, 'generate_elite_jwt_endpoint'));
        add_action('rest_api_init', array($this, 'validate_elite_jwt_endpoint'));
    }

    // Encode JWT
    public function elite_encode($iss, $data)
    {
        // Define token payload
        $token = array(
            "iss" => $iss,      // Adding the identifier to the token (issuer)
            "aud" => $iss,      // Adding the audience to the token (who can use it)
            "iat" => $this->issuedAt,   // Adding the current timestamp to the token
            "exp" => $this->expire,     // Token expiration timestamp
            "data" => $data     // Payload data
        );

        // Encode token using HMAC SHA256 algorithm
        return JWT::encode($token, $this->secrect, 'HS256');
    }

    // Decode JWT
    public function elite_decode($token)
    {
        try {
            // Decode token
            $decode = JWT::decode($token, new Key($this->secrect, 'HS256'));
            // Return decoded data
            return $decode->data;
        } catch (Exception $e) {
            // If decoding fails, return error message
            return $e->getMessage();
        }
    }

    function generate_elite_jwt($request)
    {
        $params = $request->get_params();

        $username = $params['username'];
        $password = $params['password'];

        if (!$username || !$password) {
            return new WP_Error('invalid_params', 'Invalid username or password');
        }

        try {
            $user = wp_authenticate_username_password(NULL, $username, $password);

            // Check if authentication was successful (user object returned)
            if (is_a($user, 'WP_User')) {
                $user_data = [
                    "uid" => $user->ID,
                    "name" => $user->display_name,
                    "username" => $user->user_login,
                    "email" => $user->user_email,
                ];
                return ["token" => $this->elite_encode($this->issuer, $user_data)];
            } else {
                return new WP_Error('invalid_params', 'Invalid username or password');
            }
        } catch (Exception $e) {
            return new WP_Error('invalid_params', 'Invalid username or password');
        }
    }

    function generate_elite_jwt_endpoint()
    {
        register_rest_route(
            'elite/v1',
            '/generate-token',
            array(
                'methods'  => 'POST',
                'callback' => function ($request) {
                    return $this->generate_elite_jwt($request);
                },
            )
        );
    }

    function validate_elite_jwt($request)
    {
        $params = $request->get_params();

        $token = $params['token'];
        $decoded = $this->elite_decode($token);

        if ($decoded->uid > 0) {
            return $decoded;
        } else {
            return new WP_Error('invalid_params', 'Invalid token');
        }
    }

    function validate_elite_jwt_endpoint()
    {
        register_rest_route(
            'elite/v1',
            '/validate-token',
            array(
                'methods'  => 'POST',
                'callback' => function ($request) {
                    return $this->validate_elite_jwt($request);
                },
            )
        );
    }

    public static function decode_jwt_filter()
    {
        return '$data->elite_decode($token)';
    }

    function activate()
    {
    }

    function deactivate()
    {
    }

    function uninstall()
    {
    }
}

if (class_exists('EliteJwt'))
    $elite_jwt = new EliteJwt();


// activation
register_activation_hook(__FILE__, array($elite_jwt, 'activate'));

// deactiction
register_deactivation_hook(__FILE__, array($elite_jwt, 'deactivate'));

// uninstall
