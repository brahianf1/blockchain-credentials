<?php
namespace block_credenciales\observer;

defined('MOODLE_INTERNAL') || die();

class credenciales_observer {
    public static function course_completed(\core\event\course_completed $event) {
        global $DB;

        // Obtener datos del evento
        $userid = $event->relateduserid;
        $courseid = $event->courseid;

        $user = $DB->get_record('user', array('id' => $userid));
        $course = $DB->get_record('course', array('id' => $courseid));

        // Preparar los datos para enviar al backend
        $data = array(
            'userId' => $user->id,
            'userEmail' => $user->email,
            'userName' => fullname($user),
            'courseId' => $course->id,
            'courseName' => $course->fullname,
            'completionDate' => date('c', $event->timecreated)
        );

        // URL del endpoint de nuestro backend
        $url = 'http://python-controller:3000/api/issue-credential';

        // Configurar la petición cURL
        $ch = curl_init($url);
<?php
namespace block_credenciales\observer;

use block_credenciales\logger;

defined('MOODLE_INTERNAL') || die();

class credenciales_observer {
    public static function course_completed(\core\event\course_completed $event) {
        global $DB;

        logger::info("Evento course_completed disparado", ['userid' => $event->relateduserid, 'courseid' => $event->courseid]);

        // Obtener datos del evento
        $userid = $event->relateduserid;
        $courseid = $event->courseid;

        $user = $DB->get_record('user', array('id' => $userid));
        $course = $DB->get_record('course', array('id' => $courseid));

        if (!$user || !$course) {
            logger::error("Usuario o curso no encontrado", ['userid' => $userid, 'courseid' => $courseid]);
            return;
        }

        // Preparar los datos para enviar al backend
        $data = array(
            'userId' => $user->id,
            'userEmail' => $user->email,
            'userName' => fullname($user),
            'courseId' => $course->id,
            'courseName' => $course->fullname,
            'completionDate' => date('c', $event->timecreated)
        );

        logger::info("Preparando envío de credencial", $data);

        // URL del endpoint de nuestro backend
        $url = 'http://python-controller:3000/api/issue-credential';

        // Configurar la petición cURL
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Content-Length: ' . strlen(json_encode($data))
        ));

        // Configurar timeout y manejo de errores
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

        // Ejecutar la petición
        logger::info("Enviando petición a $url");
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            logger::error("Error en cURL", $error);
            error_log('Error en cURL: ' . $error);
        } else if ($httpCode !== 200) {
            logger::error("Error HTTP del backend", ['code' => $httpCode, 'response' => $response]);
            error_log('Error HTTP: ' . $httpCode . ' - Respuesta: ' . $response);
        } else {
            logger::info("Respuesta exitosa del backend", $response);
            error_log('Credencial enviada exitosamente para usuario: ' . $user->email);
            
            // Decodificar respuesta
            $responseData = json_decode($response, true);
            
            if ($responseData) {
                // Verificar si ya existe un registro
                $existing = $DB->get_record('block_credenciales', array('userid' => $userid, 'courseid' => $courseid));
                
                $record = new \stdClass();
                $record->userid = $userid;
                $record->courseid = $courseid;
                $record->connection_id = isset($responseData['connection_id']) ? $responseData['connection_id'] : '';
                $record->invitation_url = isset($responseData['invitation_url']) ? $responseData['invitation_url'] : '';
                $record->qr_code_base64 = isset($responseData['qr_code_base64']) ? $responseData['qr_code_base64'] : (isset($responseData['qr_code']) ? $responseData['qr_code'] : '');
                $record->status = 'issued';
                $record->timemodified = time();
                
                if ($existing) {
                    $record->id = $existing->id;
                    $DB->update_record('block_credenciales', $record);
                    logger::info("Registro actualizado en DB local");
                } else {
                    $record->timecreated = time();
                    $DB->insert_record('block_credenciales', $record);
                    logger::info("Nuevo registro creado en DB local");
                }
            } else {
                logger::error("No se pudo decodificar el JSON de respuesta");
            }
        }
        
        curl_close($ch);
    }
}