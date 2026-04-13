<?php
/**
 * OID4VCI Webhook Endpoint
 * 
 * Recibe señales asíncronas desde el backend Python cuando una credencial
 * es exitosamente almacenada en la billetera del alumno.
 */

// Este script podría ejecutarse fuera del flujo normal de Moodle, 
// pero incluimos config.php para tener acceso a $DB.
define('AJAX_SCRIPT', true);
require_once('../../config.php');

// Solo aceptar peticiones POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('HTTP/1.1 405 Method Not Allowed');
    die(json_encode(['error' => 'Method not allowed']));
}

header('Content-Type: application/json');

// Leer JSON Body
$raw_input = file_get_contents('php://input');
$data = json_decode($raw_input, true);

if (!$data || !isset($data['connection_id']) || !isset($data['status'])) {
    header('HTTP/1.1 400 Bad Request');
    die(json_encode(['error' => 'Invalid payload format']));
}

$connection_id = $data['connection_id'];
$status = $data['status'];

error_log("WEBHOOK_CREDENCIALES: Recibido payload de Python. connection_id=" . $connection_id . ", status=" . $status);

// Localizar el registro en Moodle
global $DB;
$record = $DB->get_record('block_credenciales', array('connection_id' => $connection_id));

if (!$record) {
    header('HTTP/1.1 404 Not Found');
    die(json_encode(['error' => 'Credential not found for the given connection_id']));
}

// Actualizar el estado y el timestamp de modificación (Momento exacto de claim en Billetera)
$record->status = $status; // debe ser 'claimed'
$record->timemodified = time();

if ($DB->update_record('block_credenciales', $record)) {
    // Éxito
    echo json_encode([
        'success' => true,
        'message' => 'Credential status updated successfully',
        'timemodified' => $record->timemodified
    ]);
} else {
    // Fallo de DB
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode(['error' => 'Failed to update database']);
}
