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

/**
 * Format a Moodle final grade the way the backend does for the credential hash.
 *
 * Mirrors the Python backend (moodle_queries.get_user_grade): a missing grade
 * becomes the literal "Aprobado", otherwise the numeric grade rounded to one
 * decimal (e.g. 8 -> "8.0", 9.5 -> "9.5"). Kept pure so it can be unit tested
 * against the backend's behaviour.
 *
 * @param float|string|null $finalgrade Raw finalgrade from mdl_grade_grades.
 * @return string Grade token feeding the credential hash.
 */
function block_credenciales_format_grade($finalgrade) {
    if ($finalgrade === null || $finalgrade === '') {
        return 'Aprobado';
    }
    return number_format((float) $finalgrade, 1, '.', '');
}

/**
 * Resolve the course final grade exactly as the backend's verification does.
 *
 * Uses the course-level grade item (grade_items.itemtype = 'course'), the same
 * source the Python verifier reads, so the recomputed hash matches end to end.
 *
 * @param int $userid
 * @param int $courseid
 * @return string Grade token ("Aprobado" or one-decimal numeric).
 */
function block_credenciales_get_course_grade($userid, $courseid) {
    global $DB;

    $sql = "SELECT gg.finalgrade
              FROM {grade_grades} gg
              JOIN {grade_items} gi ON gi.id = gg.itemid
             WHERE gg.userid = :userid
               AND gi.courseid = :courseid
               AND gi.itemtype = 'course'";
    $rec = $DB->get_record_sql($sql, ['userid' => $userid, 'courseid' => $courseid], IGNORE_MULTIPLE);

    return block_credenciales_format_grade($rec ? $rec->finalgrade : null);
}

/**
 * Compute the canonical SHA-256 credential hash.
 *
 * CROSS-LANGUAGE CONTRACT: this is the byte-for-byte twin of the Python
 * backend's utils/hashing.compute_credential_hash. The backend remains the
 * single source of truth (it anchors this exact hash on-chain); this PHP twin
 * exists only so the LMS can build verification links without an extra
 * round-trip. Parity is guarded by tests/lib_test.php with known vectors —
 * if either side changes, the test fails before production breaks.
 *
 * @param string $student_id
 * @param string $course_id
 * @param string $completion_date ISO-8601 UTC, e.g. gmdate('c', $timecreated).
 * @param string $grade
 * @return string 64-char lowercase SHA-256 hex digest.
 */
function block_credenciales_compute_credential_hash($student_id, $course_id, $completion_date, $grade) {
    return hash('sha256', $student_id . $course_id . $completion_date . $grade);
}

/**
 * Build the public verification URL on the portal frontend for a hash.
 *
 * Single source of truth for the link contract: the portal route
 * /verificar/{hash}, with the base taken from the configurable portal_url so
 * it never drifts from the deployed frontend.
 *
 * @param string $hash 64-char SHA-256 credential hash.
 * @return string Absolute public verification URL.
 */
function block_credenciales_get_verify_url($hash) {
    $config = get_config('block_credenciales');
    $portal_url = !empty($config->portal_url)
        ? rtrim($config->portal_url, '/')
        : 'https://portal-credenciales.utnpf.site';

    return $portal_url . '/verificar/' . $hash;
}

/**
 * Build the backend Open Graph "embed" URL for a credential.
 *
 * This backend page renders a rich social preview card (LinkedIn, WhatsApp…)
 * and redirects human visitors to the canonical portal verification page.
 * It exists because the portal SPA cannot serve Open Graph tags to crawlers
 * (they don't run JavaScript).
 *
 * @param string $hash 64-char SHA-256 credential hash.
 * @return string Absolute embed URL on the verification API.
 */
function block_credenciales_get_embed_url($hash) {
    $config = get_config('block_credenciales');
    $api = !empty($config->verification_api_url)
        ? rtrim($config->verification_api_url, '/')
        : 'https://api-credenciales.utnpf.site';

    return $api . '/api/public/verify/' . $hash . '/embed';
}

/**
 * Build a LinkedIn "share as post" URL pointing at the Open Graph embed page,
 * so the published post renders a rich preview card.
 *
 * @param string $hash 64-char SHA-256 credential hash.
 * @return string LinkedIn share-offsite URL.
 */
function block_credenciales_get_share_post_url($hash) {
    return 'https://www.linkedin.com/sharing/share-offsite/?url='
        . urlencode(block_credenciales_get_embed_url($hash));
}

/**
 * Build a LinkedIn "Add to Profile" deep-link for a microcredential.
 *
 * Uses LinkedIn's official certification prefill (Licenses & Certifications),
 * the standard integration for credential issuers — far better UX than a plain
 * share, as it lands the achievement directly in the holder's profile with the
 * public verification URL attached.
 *
 * @param string $cert_name  Credential / course name.
 * @param string $org_name   Issuing organization.
 * @param int    $year       Issue year.
 * @param int    $month       Issue month (1-12).
 * @param string $verify_url Public verification URL.
 * @param string $cert_id    Credential hash (public identifier).
 * @return string LinkedIn deep-link URL.
 */
function block_credenciales_get_linkedin_url($cert_name, $org_name, $year, $month, $verify_url, $cert_id) {
    $params = array(
        'startTask'        => 'CERTIFICATION_NAME',
        'name'             => $cert_name,
        'organizationName' => $org_name,
        'issueYear'        => (string) $year,
        'issueMonth'       => (string) $month,
        'certUrl'          => $verify_url,
        'certId'           => $cert_id,
    );

    return 'https://www.linkedin.com/profile/add?' . http_build_query($params);
}
