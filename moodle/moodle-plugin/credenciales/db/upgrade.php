<?php
defined('MOODLE_INTERNAL') || die();

function xmldb_block_credenciales_upgrade($oldversion) {
    global $DB;
    $dbman = $DB->get_manager();

    if ($oldversion < 2024080201) {
        // Define table block_credenciales_logs to be created
        $table = new xmldb_table('block_credenciales_logs');

        // Adding fields to table block_credenciales_logs
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('level', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, 'info');
        $table->add_field('message', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('details', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);

        // Adding keys to table block_credenciales_logs
        $table->add_key('primary', XMLDB_KEY_PRIMARY, array('id'));

        // Adding indexes to table block_credenciales_logs
        $table->add_index('timecreated_idx', XMLDB_INDEX_NOTUNIQUE, array('timecreated'));

        // Conditionally launch create table for block_credenciales_logs
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }

        // Credenciales savepoint reached
        upgrade_block_savepoint(true, 2024080201, 'credenciales');
    }

    return true;
}
