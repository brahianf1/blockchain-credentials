<?php
require_once('../../config.php');
// Moodle does not auto-load a block's lib.php for standalone scripts, so we
// include it explicitly to use the credential-hash and share-link helpers.
require_once(__DIR__ . '/lib.php');

require_login();

$PAGE->set_url(new moodle_url('/blocks/credenciales/my_certificates.php'));
$PAGE->set_context(context_user::instance($USER->id));
$PAGE->set_pagelayout('standard');
$PAGE->set_title(get_string('my_certificates', 'block_credenciales'));
$PAGE->set_heading(get_string('my_certificates', 'block_credenciales'));

// Add breadcrumbs
$PAGE->navbar->add(get_string('my_certificates', 'block_credenciales'));

echo $OUTPUT->header();

// Get all credentials for the user
$credentials = $DB->get_records('block_credenciales', array('userid' => $USER->id), 'timecreated DESC');

$data = [
    'has_certificates' => !empty($credentials),
    'certificates' => []
];

// Para fines de la tesis y cumplimiento de la Ley 25.326 de Protección de Datos 
// Personales en Argentina, el DNI se enmascara para evitar exponer datos reales 
// en las capturas de pantalla de la tesis.
$user_dni = 'XX.XXX.XXX';

if ($credentials) {
    foreach ($credentials as $cred) {
        $course = $DB->get_record('course', array('id' => $cred->courseid));
        
        $is_claimed = ($cred->status === 'issued' || $cred->status === 'claimed');

        // Real public verification URL on the portal frontend, keyed by the
        // canonical SHA-256 credential hash — the same hash the backend anchors
        // on-chain and recomputes when verifying. Computed here (not stored) via
        // the shared, test-validated helpers so the link works for every
        // credential without an extra round-trip to the backend.
        $completion_date_utc = gmdate('c', $cred->timecreated);
        $grade = block_credenciales_get_course_grade($USER->id, $cred->courseid);
        $credential_hash = block_credenciales_compute_credential_hash(
            (string) $USER->id,
            (string) $cred->courseid,
            $completion_date_utc,
            $grade
        );
        $public_verify_url = block_credenciales_get_verify_url($credential_hash);

        // "Compartir Logro" → LinkedIn Add to Profile (Licenses & Certifications).
        $linkedin_share_url = block_credenciales_get_linkedin_url(
            $course ? $course->fullname : 'Microcredencial',
            get_config('block_credenciales', 'organization_name') ?: 'Universidad',
            (int) gmdate('Y', $cred->timecreated),
            (int) gmdate('n', $cred->timecreated),
            $public_verify_url,
            $credential_hash
        );

        $data['certificates'][] = [
            'student_name' => fullname($USER),
            'student_dni' => $user_dni,
            'course_name' => $course ? $course->fullname : 'Unknown Course',
            'date' => userdate($cred->timecreated, get_string('strftimedate', 'core_langconfig')),
            'exact_completion_time' => userdate($cred->timecreated, '%d/%m/%Y %H:%M'),
            'exact_claimed_time' => userdate($cred->timemodified, '%d/%m/%Y %H:%M'),
            'year' => userdate($cred->timecreated, '%Y'),
            'qr_code' => $cred->qr_code_base64, // The DID Wallet QR code
            'invitation_url' => $cred->invitation_url, // URL for Desktop
            'status' => $cred->status,
            'is_pending' => !$is_claimed,
            'is_claimed' => $is_claimed,
            'public_verify_url' => $public_verify_url,
            'credential_hash' => $credential_hash,
            'linkedin_share_url' => $linkedin_share_url,
            'share_post_url' => block_credenciales_get_share_post_url($credential_hash),
            'issue_date_label' => userdate($cred->timecreated, '%B %Y'),
            'org_name' => get_config('block_credenciales', 'organization_name') ?: 'Universidad',
            'cert_id' => $cred->id,
            'hours' => '120' // Static illustration mock for 'horas reloj'
        ];
    }
}

echo $OUTPUT->render_from_template('block_credenciales/dashboard', $data);

echo $OUTPUT->footer();
