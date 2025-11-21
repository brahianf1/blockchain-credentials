<?php
namespace block_credenciales;

defined('MOODLE_INTERNAL') || die();

class logger {
    /**
     * Log an info message
     */
    public static function info($message, $details = null) {
        self::log('info', $message, $details);
    }

    /**
     * Log an error message
     */
    public static function error($message, $details = null) {
        self::log('error', $message, $details);
    }

    /**
     * Write log to database
     */
    private static function log($level, $message, $details) {
        global $DB;

        if (is_array($details) || is_object($details)) {
            $details = json_encode($details, JSON_PRETTY_PRINT);
        }

        $record = new \stdClass();
        $record->level = $level;
        $record->message = $message;
        $record->details = $details;
        $record->timecreated = time();

        try {
            $DB->insert_record('block_credenciales_logs', $record);
        } catch (\Exception $e) {
            // Fallback to error_log if DB fails
            error_log("Block Credenciales Logger Failed: " . $e->getMessage());
            error_log("Original Message: [$level] $message");
        }
    }
}
