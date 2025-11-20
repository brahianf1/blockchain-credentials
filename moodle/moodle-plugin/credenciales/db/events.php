<?php
defined('MOODLE_INTERNAL') || die();
$observers = array(
    array(
        'eventname'   => '\core\event\course_completed',
        'callback'    => '\block_credenciales\observer\credenciales_observer::course_completed',
    ),
);