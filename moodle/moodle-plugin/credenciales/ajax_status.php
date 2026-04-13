<?php
/**
 * AJAX Endpoint para consultar el estado en tiempo real.
 * Usado por el dashboard para la carga reactiva de la credencial.
 */

define('AJAX_SCRIPT', true);
require_once('../../config.php');

require_login();

header('Content-Type: application/json');

$cert_id = optional_param('cert_id', 0, PARAM_INT);

if (!$cert_id) {
    header('HTTP/1.1 400 Bad Request');
    die(json_encode(['error' => 'Missing cert_id']));
}

global $DB, $USER;

// Retrieve the record
$record = $DB->get_record('block_credenciales', ['id' => $cert_id, 'userid' => $USER->id]);

if (!$record) {
    header('HTTP/1.1 404 Not Found');
    die(json_encode(['error' => 'Credential not found or access denied']));
}

echo json_encode([
    'status' => $record->status,
    'exact_claimed_time' => $record->timemodified ? userdate($record->timemodified, '%d/%m/%Y %H:%M') : null
]);
