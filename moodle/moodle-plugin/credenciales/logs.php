<?php
require_once('../../config.php');
require_once($CFG->libdir.'/adminlib.php');

require_login();
$context = context_system::instance();
require_capability('moodle/site:config', $context);

$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/blocks/credenciales/logs.php'));
$PAGE->set_title(get_string('pluginname', 'block_credenciales') . ' - Logs');
$PAGE->set_heading(get_string('pluginname', 'block_credenciales') . ' - Logs');

echo $OUTPUT->header();
echo $OUTPUT->heading('Registros del Plugin de Credenciales');

// Botón de volver a configuración
echo '<div style="margin-bottom: 20px;">
    <a href="' . $CFG->wwwroot . '/admin/settings.php?section=block_credenciales" class="btn btn-secondary">
        <i class="fa fa-arrow-left"></i> Volver a Configuración
    </a>
</div>';

$logs = $DB->get_records('block_credenciales_logs', null, 'timecreated DESC', '*', 0, 100);

if (empty($logs)) {
    echo $OUTPUT->notification('No hay registros disponibles.', 'info');
} else {
    echo '<table class="generaltable">';
    echo '<thead><tr>
            <th>Fecha</th>
            <th>Nivel</th>
            <th>Mensaje</th>
            <th>Detalles</th>
          </tr></thead>';
    echo '<tbody>';
    
    foreach ($logs as $log) {
        $levelClass = ($log->level === 'error') ? 'badge badge-danger' : 'badge badge-info';
        $levelStyle = ($log->level === 'error') ? 'background-color: #dc3545; color: white;' : 'background-color: #17a2b8; color: white;';
        
        echo '<tr>';
        echo '<td>' . userdate($log->timecreated) . '</td>';
        echo '<td><span class="' . $levelClass . '" style="padding: 5px; border-radius: 4px; ' . $levelStyle . '">' . strtoupper($log->level) . '</span></td>';
        echo '<td>' . s($log->message) . '</td>';
        echo '<td>';
        if (!empty($log->details)) {
            echo '<pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; max-height: 200px; overflow: auto;">' . s($log->details) . '</pre>';
        }
        echo '</td>';
        echo '</tr>';
    }
    
    echo '</tbody>';
    echo '</table>';
}

echo $OUTPUT->footer();
