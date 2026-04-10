<?php
defined('MOODLE_INTERNAL') || die();
$plugin->component = 'block_credenciales';
$plugin->version   = 2026041000; // Force upgrade to reload applicable_formats and AMD cache
$plugin->requires  = 2021112900; // Moodle 4.0