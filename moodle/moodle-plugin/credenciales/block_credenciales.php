<?php
defined('MOODLE_INTERNAL') || die();

class block_credenciales extends block_base {
    public function init() {
        $this->title = get_string('pluginname', 'block_credenciales');
    }

    public function get_content() {
        global $DB, $USER, $COURSE, $OUTPUT, $PAGE;

        if ($this->content !== null) {
            return $this->content;
        }

        $this->content = new stdClass;
        $this->content->text = '';
        $this->content->footer = '';

        // Solo mostrar si estamos dentro de un curso (no en la página principal del sitio)
        if ($COURSE->id == SITEID) {
            return $this->content;
        }

        // Obtener configuración global
        $config = get_config('block_credenciales');
        $view_mode = isset($config->default_view_mode) ? $config->default_view_mode : 'modal';
        $org_name = isset($config->organization_name) ? $config->organization_name : 'Universidad';
        $brand_color = isset($config->brand_color) ? $config->brand_color : '#1976d2';

        // Verificar si el usuario tiene una credencial para este curso
        $credential = $DB->get_record('block_credenciales', array('userid' => $USER->id, 'courseid' => $COURSE->id));

        $renderer = $PAGE->get_renderer('block_credenciales');

        if ($credential) {
            // Datos para la plantilla
            $data = [
                'has_credential' => true,
                'qr_code' => $credential->qr_code_base64,
                'invitation_url' => $credential->invitation_url,
                'student_name' => fullname($USER),
                'course_name' => $COURSE->fullname,
                'date' => userdate($credential->timecreated, get_string('strftimedate', 'core_langconfig')),
                'org_name' => $org_name,
                'brand_color' => $brand_color,
                'is_modal' => ($view_mode === 'modal'),
                'dashboard_url' => new moodle_url('/blocks/credenciales/my_certificates.php')
            ];
            
            // Renderizar plantilla principal
            $this->content->text = $renderer->render_credential_status($data);

            // Si es modal, incluir el modal en el footer o al final del body
            if ($view_mode === 'modal') {
                $this->content->text .= $renderer->render_certificate_modal($data);
                // Incluir JS para el modal
                $this->page->requires->js_call_amd('block_credenciales/modal_viewer', 'init');
            }

        } else {
            // Mensaje por defecto si no hay credencial
            $data = [
                'has_credential' => false,
                'message' => get_string('complete_course_message', 'block_credenciales'),
                'dashboard_url' => new moodle_url('/blocks/credenciales/my_certificates.php')
            ];
            $this->content->text = $renderer->render_credential_status($data);
        }

        return $this->content;
    }

    // Permitir configuración global
    public function has_config() {
        return true;
    }
    
    // Permitir configuración de instancia (opcional, por ahora desactivado para forzar global)
    public function instance_allow_config() {
        return false;
    }
}
