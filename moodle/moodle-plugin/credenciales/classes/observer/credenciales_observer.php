<?php
namespace local_credenciales\observer;

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
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            error_log('Error en cURL: ' . curl_error($ch));
        } else if ($httpCode !== 200) {
            error_log('Error HTTP: ' . $httpCode . ' - Respuesta: ' . $response);
        } else {
            error_log('Credencial enviada exitosamente para usuario: ' . $user->email);
        }
        
        curl_close($ch);
    }
}