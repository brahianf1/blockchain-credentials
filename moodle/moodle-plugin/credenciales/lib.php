<?php
/**
 * Library functions for block_credenciales.
 *
 * Provides JWT generation for portal authentication redirect.
 *
 * @package   block_credenciales
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Base64url-encode data (RFC 7515 §2).
 *
 * @param string $data Raw bytes to encode.
 * @return string URL-safe base64 string without padding.
 */
function block_credenciales_base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Generate an HS256-signed JWT (RFC 7519) using pure PHP.
 *
 * No external libraries required — relies only on hash_hmac which is
 * available in every Moodle-supported PHP build.
 *
 * @param array  $payload Associative array of claims.
 * @param string $secret  Shared secret (hex or raw string).
 * @return string Compact JWS (header.payload.signature).
 */
function block_credenciales_generate_jwt(array $payload, $secret) {
    $header = block_credenciales_base64url_encode(json_encode([
        'alg' => 'HS256',
        'typ' => 'JWT',
    ]));

    $body = block_credenciales_base64url_encode(json_encode($payload));

    $signature = block_credenciales_base64url_encode(
        hash_hmac('sha256', "{$header}.{$body}", $secret, true)
    );

    return "{$header}.{$body}.{$signature}";
}

/**
 * Build a portal redirect URL with an embedded short-lived JWT.
 *
 * The token carries the student's Moodle identity so the portal backend
 * can create or update the portal account on first access.
 *
 * @param stdClass $user Moodle user object (id, email, firstname, lastname).
 * @return string Full portal URL with ?token=<jwt> query parameter.
 */
function block_credenciales_get_portal_url($user) {
    $config = get_config('block_credenciales');

    $secret = isset($config->portal_jwt_secret) ? $config->portal_jwt_secret : '';
    $portal_url = isset($config->portal_url) ? $config->portal_url : 'https://portal-credenciales.utnpf.site';

    if (empty($secret)) {
        // Fallback: send without token — portal will show an error.
        return $portal_url;
    }

    $now = time();
    $payload = [
        'moodle_user_id' => (int) $user->id,
        'email'          => $user->email,
        'full_name'      => trim($user->firstname . ' ' . $user->lastname),
        'is_admin'       => is_siteadmin($user->id),
        'iat'            => $now,
        'exp'            => $now + 300, // 5-minute TTL — sufficient for redirect.
    ];

    $token = block_credenciales_generate_jwt($payload, $secret);

    // Use /auth/moodle-callback path on the portal frontend.
    $separator = (strpos($portal_url, '?') !== false) ? '&' : '?';
    return $portal_url . '/auth/moodle-callback' . $separator . 'token=' . urlencode($token);
}
