<?php
namespace block_credenciales\output;

defined('MOODLE_INTERNAL') || die;

use plugin_renderer_base;

class renderer extends plugin_renderer_base {
    /**
     * Render the credential status block content
     */
    public function render_credential_status($data) {
        return $this->render_from_template('block_credenciales/credential_status', $data);
    }

    /**
     * Render the certificate modal
     */
    public function render_certificate_modal($data) {
        return $this->render_from_template('block_credenciales/certificate_modal', $data);
    }
}
