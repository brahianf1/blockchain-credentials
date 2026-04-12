<?php
require_once('../../config.php');

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

// Extract DNI (Assuming custom profile field 'dni' exists, otherwise simulate a realistic Argentine DNI for dev)
$user_dni = null;
if ($dni_field = $DB->get_record('user_info_field', array('shortname' => 'dni'))) {
    if ($dni_data = $DB->get_record('user_info_data', array('userid' => $USER->id, 'fieldid' => $dni_field->id))) {
        $user_dni = $dni_data->data;
    }
}

// Dev Mock: Si no hay DNI, generamos uno realista (XX.XXX.XXX) basado en el ID de usuario para que sea consistente
if (empty($user_dni)) {
    // Usamos el id del usuario como semilla para que el DNI no cambie en cada recarga
    srand($USER->id + 42000000); 
    $random_dni = mt_rand(40000000, 48999999);
    $user_dni = number_format($random_dni, 0, ',', '.'); // Ejemplo: 45.123.456
}

if ($credentials) {
    foreach ($credentials as $cred) {
        $course = $DB->get_record('course', array('id' => $cred->courseid));
        
        $is_claimed = ($cred->status === 'issued' || $cred->status === 'claimed');
        // Mocking the public verification URL
        $public_verify_url = $CFG->wwwroot . "/blocks/credenciales/public_verify.php?uuid=" . $cred->id; // Placeholder architecture
        $linkedin_share_url = "https://www.linkedin.com/sharing/share-offsite/?url=" . urlencode($public_verify_url);

        $data['certificates'][] = [
            'student_name' => fullname($USER),
            'student_dni' => $user_dni,
            'course_name' => $course ? $course->fullname : 'Unknown Course',
            'date' => userdate($cred->timecreated, get_string('strftimedate', 'core_langconfig')),
            'exact_time' => userdate($cred->timecreated, '%d/%m/%Y %H:%M'),
            'year' => userdate($cred->timecreated, '%Y'),
            'qr_code' => $cred->qr_code_base64, // The DID Wallet QR code
            'invitation_url' => $cred->invitation_url, // URL for Desktop
            'status' => $cred->status,
            'is_pending' => !$is_claimed,
            'is_claimed' => $is_claimed,
            'public_verify_url' => $public_verify_url,
            'linkedin_share_url' => $linkedin_share_url,
            'org_name' => get_config('block_credenciales', 'organization_name') ?: 'Universidad',
            'cert_id' => $cred->id,
            'hours' => '120' // Static illustration mock for 'horas reloj'
        ];
    }
}

echo $OUTPUT->render_from_template('block_credenciales/dashboard', $data);

echo $OUTPUT->footer();
