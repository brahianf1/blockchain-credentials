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

if ($credentials) {
    foreach ($credentials as $cred) {
        $course = $DB->get_record('course', array('id' => $cred->courseid));
        $data['certificates'][] = [
            'course_name' => $course ? $course->fullname : 'Unknown Course',
            'date' => userdate($cred->timecreated, get_string('strftimedate', 'core_langconfig')),
            'qr_code' => $cred->qr_code_base64,
            'invitation_url' => $cred->invitation_url,
            'status' => $cred->status
        ];
    }
}

echo $OUTPUT->render_from_template('block_credenciales/dashboard', $data);

echo $OUTPUT->footer();
