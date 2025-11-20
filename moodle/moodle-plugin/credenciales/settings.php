<?php
defined('MOODLE_INTERNAL') || die;

if ($ADMIN->fulltree) {
    // Default View Mode
    $settings->add(new admin_setting_configselect(
        'block_credenciales/default_view_mode',
        get_string('default_view_mode', 'block_credenciales'),
        get_string('default_view_mode_desc', 'block_credenciales'),
        'modal',
        array(
            'modal' => get_string('view_mode_modal', 'block_credenciales'),
            'side' => get_string('view_mode_side', 'block_credenciales')
        )
    ));

    // Organization Name
    $settings->add(new admin_setting_configtext(
        'block_credenciales/organization_name',
        get_string('organization_name', 'block_credenciales'),
        get_string('organization_name_desc', 'block_credenciales'),
        'Universidad Tecnológica',
        PARAM_TEXT
    ));

    // Brand Color
    $settings->add(new admin_setting_configtext(
        'block_credenciales/brand_color',
        get_string('brand_color', 'block_credenciales'),
        get_string('brand_color_desc', 'block_credenciales'),
        '#1976d2',
        PARAM_TEXT
    ));
}
