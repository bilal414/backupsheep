<?php
/**
 * Plugin Name: BackupSheep Secure Connector
 * Plugin URI:  https://backupsheep.com/
 * Description: Authenticated, replay-resistant BackupSheep integration for UpdraftPlus.
 * Version:     2.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author:      BackupSheep
 * License:     GPLv3 or later
 * Text Domain: backupsheep
 */

if (!defined('ABSPATH')) {
    exit;
}

define('BACKUPSHEEP_V2_PROTOCOL', '2');
define('BACKUPSHEEP_V2_SIGNATURE_DOMAIN', 'backupsheep-wordpress-v2');
define('BACKUPSHEEP_V2_MAX_BODY_BYTES', 65536);
define('BACKUPSHEEP_V2_CLOCK_SKEW_SECONDS', 300);
define('BACKUPSHEEP_V2_OPTION', 'backupsheep_v2_options');
define('BACKUPSHEEP_V2_NONCE_PREFIX', 'backupsheep_v2_nonce_');

/** Return a generic authentication failure without exposing which check failed. */
function backupsheep_v2_auth_error()
{
    return new WP_Error(
        'backupsheep_v2_unauthorized',
        __('BackupSheep request authentication failed.', 'backupsheep'),
        array('status' => 401)
    );
}

/** Fetch the configured shared secret without exposing it through REST responses. */
function backupsheep_v2_secret()
{
    $options = get_option(BACKUPSHEEP_V2_OPTION, array());
    $secret = is_array($options) && isset($options['integration_secret'])
        ? (string) $options['integration_secret']
        : '';
    if (!preg_match('/\A[A-Za-z0-9_-]{24,512}\z/D', $secret)) {
        return '';
    }
    return $secret;
}

/** Opportunistically bound replay-ledger growth even when WP-Cron is disabled. */
function backupsheep_v2_cleanup_nonces()
{
    global $wpdb;
    $like = $wpdb->esc_like(BACKUPSHEEP_V2_NONCE_PREFIX) . '%';
    $names = $wpdb->get_col(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(option_value AS UNSIGNED) < %d ORDER BY option_id ASC LIMIT 1000",
            $like,
            time()
        )
    );
    foreach (is_array($names) ? $names : array() as $name) {
        // Use the public API so WordPress's object cache cannot retain a deleted nonce.
        if (is_string($name) && strpos($name, BACKUPSHEEP_V2_NONCE_PREFIX) === 0) {
            delete_option($name);
        }
    }
}
add_action('backupsheep_v2_cleanup_nonces', 'backupsheep_v2_cleanup_nonces');

/**
 * Verify the exact body, route, timestamp and nonce before any callback runs.
 *
 * The secret itself never appears in a request header or URL. The key identifier is
 * only a truncated SHA-256 selector. add_option() is a database-unique atomic insert,
 * so two concurrent deliveries of one signed nonce cannot both pass.
 */
function backupsheep_v2_authorize(WP_REST_Request $request)
{
    $protocol = (string) $request->get_header('x-backupsheep-protocol');
    $key_id = (string) $request->get_header('x-backupsheep-key-id');
    $timestamp_raw = (string) $request->get_header('x-backupsheep-timestamp');
    $nonce = (string) $request->get_header('x-backupsheep-nonce');
    $signed_route = (string) $request->get_header('x-backupsheep-route');
    $content_sha256 = (string) $request->get_header('x-backupsheep-content-sha256');
    $signature = (string) $request->get_header('x-backupsheep-signature');
    $body = (string) $request->get_body();
    $route = basename((string) $request->get_route());

    if (
        $protocol !== BACKUPSHEEP_V2_PROTOCOL
        || strlen($body) === 0
        || strlen($body) > BACKUPSHEEP_V2_MAX_BODY_BYTES
        || !preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D', $route)
        || !hash_equals($route, $signed_route)
        || !preg_match('/\A[0-9]{1,12}\z/D', $timestamp_raw)
        || !preg_match('/\A[0-9a-f]{32}\z/D', $nonce)
        || !preg_match('/\A[0-9a-f]{64}\z/D', $content_sha256)
        || !preg_match('/\A[0-9a-f]{64}\z/D', $signature)
        || !preg_match('/\A[0-9a-f]{32}\z/D', $key_id)
    ) {
        return backupsheep_v2_auth_error();
    }

    $timestamp = (int) $timestamp_raw;
    if (abs(time() - $timestamp) > BACKUPSHEEP_V2_CLOCK_SKEW_SECONDS) {
        return backupsheep_v2_auth_error();
    }
    $actual_body_sha256 = hash('sha256', $body);
    if (!hash_equals($actual_body_sha256, $content_sha256)) {
        return backupsheep_v2_auth_error();
    }

    $secret = backupsheep_v2_secret();
    if ($secret === '' || !hash_equals(substr(hash('sha256', $secret), 0, 32), $key_id)) {
        return backupsheep_v2_auth_error();
    }
    $canonical = implode("\n", array(
        BACKUPSHEEP_V2_SIGNATURE_DOMAIN,
        BACKUPSHEEP_V2_PROTOCOL,
        'POST',
        $route,
        $timestamp_raw,
        $nonce,
        $content_sha256,
    ));
    $expected = hash_hmac('sha256', $canonical, $secret);
    if (!hash_equals($expected, $signature)) {
        return backupsheep_v2_auth_error();
    }

    $nonce_name = BACKUPSHEEP_V2_NONCE_PREFIX . $key_id . '_' . $nonce;
    if (!add_option($nonce_name, (string) (time() + 600), '', false)) {
        return backupsheep_v2_auth_error();
    }
    // The nonce is generated randomly by BackupSheep. This deterministic sample
    // avoids random_int() exceptions turning an authenticated request into a 500.
    if (hexdec(substr($nonce, 0, 2)) === 0) {
        backupsheep_v2_cleanup_nonces();
    }
    return true;
}

/** Register only the signed v2 routes. There is deliberately no v1 fallback. */
function backupsheep_v2_register_routes()
{
    $routes = array(
        'validate' => 'backupsheep_v2_validate',
        'backup' => 'backupsheep_v2_backup',
        'status' => 'backupsheep_v2_status',
        'files' => 'backupsheep_v2_files',
        'download' => 'backupsheep_v2_download',
        'delete' => 'backupsheep_v2_delete',
        'rebuild_history' => 'backupsheep_v2_rebuild_history',
    );
    foreach ($routes as $route => $callback) {
        register_rest_route(
            'backupsheep/v2',
            '/' . $route,
            array(
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => $callback,
                'permission_callback' => 'backupsheep_v2_authorize',
            )
        );
    }
}
add_action('rest_api_init', 'backupsheep_v2_register_routes');

function backupsheep_v2_payload(WP_REST_Request $request)
{
    $payload = $request->get_json_params();
    return is_array($payload) ? $payload : array();
}

function backupsheep_v2_response($data, $status = 200)
{
    $response = new WP_REST_Response($data, $status);
    $response->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    $response->header('Pragma', 'no-cache');
    $response->header('X-Content-Type-Options', 'nosniff');
    return $response;
}

function backupsheep_v2_updraftplus()
{
    global $updraftplus;
    if (!is_object($updraftplus)) {
        return new WP_Error(
            'backupsheep_v2_updraft_unavailable',
            __('UpdraftPlus is unavailable.', 'backupsheep'),
            array('status' => 503)
        );
    }
    return $updraftplus;
}

function backupsheep_v2_backup_uuid($payload)
{
    $raw = isset($payload['backup_uuid']) ? (string) $payload['backup_uuid'] : '';
    $value = sanitize_key($raw);
    if ($value === '' || strlen($value) > 64 || !hash_equals($raw, $value)) {
        return new WP_Error(
            'backupsheep_v2_invalid_backup',
            __('The backup identifier is invalid.', 'backupsheep'),
            array('status' => 400)
        );
    }
    return $value;
}

function backupsheep_v2_validate()
{
    $active = apply_filters('active_plugins', get_option('active_plugins', array()));
    return backupsheep_v2_response(array(
        'protocol' => 2,
        'plugins' => array(
            // This authenticated callback can execute only while this plugin is active.
            'backupsheep' => true,
            'updraftplus' => in_array('updraftplus/updraftplus.php', $active, true),
        ),
    ));
}

function backupsheep_v2_backup(WP_REST_Request $request)
{
    $payload = backupsheep_v2_payload($request);
    $backup_uuid = backupsheep_v2_backup_uuid($payload);
    if (is_wp_error($backup_uuid)) {
        return $backup_uuid;
    }
    $include = isset($payload['include']) ? (int) $payload['include'] : 1;
    if (!in_array($include, array(1, 2, 3), true)) {
        return new WP_Error(
            'backupsheep_v2_invalid_include',
            __('The backup include mode is invalid.', 'backupsheep'),
            array('status' => 400)
        );
    }
    $arguments = array('nocloud' => 1, 'use_timestamp' => 0, 'use_nonce' => $backup_uuid);
    if ($include === 3) {
        do_action('updraft_backupnow_backup', $arguments);
    } elseif ($include === 2) {
        do_action('updraft_backupnow_backup_database', $arguments);
    } else {
        do_action('updraft_backupnow_backup_all', $arguments);
    }
    return backupsheep_v2_response(array('backup_uuid' => $backup_uuid));
}

function backupsheep_v2_status(WP_REST_Request $request)
{
    $updraft = backupsheep_v2_updraftplus();
    if (is_wp_error($updraft)) {
        return $updraft;
    }
    $backup_uuid = backupsheep_v2_backup_uuid(backupsheep_v2_payload($request));
    if (is_wp_error($backup_uuid)) {
        return $backup_uuid;
    }
    $status = $updraft->found_backup_complete_in_logfile($backup_uuid);
    $log_path = (string) $updraft->get_logfile_name($backup_uuid);
    $log_file = basename($log_path);
    return backupsheep_v2_response(array(
        'status' => $status,
        'log_file' => $log_file,
        'protocol' => 2,
    ));
}

function backupsheep_v2_files(WP_REST_Request $request)
{
    $updraft = backupsheep_v2_updraftplus();
    if (is_wp_error($updraft)) {
        return $updraft;
    }
    $backup_uuid = backupsheep_v2_backup_uuid(backupsheep_v2_payload($request));
    if (is_wp_error($backup_uuid)) {
        return $backup_uuid;
    }
    $matches = glob(rtrim($updraft->backups_dir_location(), '/\\') . '/*_' . $backup_uuid . '-*');
    $files = array();
    foreach (is_array($matches) ? $matches : array() as $path) {
        if (is_file($path)) {
            $files[] = basename($path);
        }
    }
    sort($files, SORT_STRING);
    return backupsheep_v2_response(array('files' => $files));
}

/** Return one generic response for missing files and run/file mismatches. */
function backupsheep_v2_file_not_found()
{
    return new WP_Error(
        'backupsheep_v2_file_not_found',
        __('The backup file was not found.', 'backupsheep'),
        array('status' => 404)
    );
}

/** Resolve an exact regular file that remains inside UpdraftPlus's backup directory. */
function backupsheep_v2_backup_file($payload)
{
    $raw = isset($payload['backup_file']) ? (string) $payload['backup_file'] : '';
    if (
        $raw === ''
        || strlen($raw) > 255
        || basename($raw) !== $raw
        || sanitize_file_name($raw) !== $raw
    ) {
        return new WP_Error(
            'backupsheep_v2_invalid_file',
            __('The backup file name is invalid.', 'backupsheep'),
            array('status' => 400)
        );
    }
    $updraft = backupsheep_v2_updraftplus();
    if (is_wp_error($updraft)) {
        return $updraft;
    }
    $directory = realpath((string) $updraft->backups_dir_location());
    $path = $directory === false ? false : realpath($directory . DIRECTORY_SEPARATOR . $raw);
    if (
        $directory === false
        || $path === false
        || !is_file($path)
        || strpos($path, $directory . DIRECTORY_SEPARATOR) !== 0
    ) {
        return backupsheep_v2_file_not_found();
    }
    return array('name' => $raw, 'path' => $path);
}

/**
 * Confirm that a resolved file is an exact member of one UpdraftPlus backup run.
 *
 * Matching both the requested basename and resolved path prevents an authenticated
 * request from using an alias to reach another historical file in the backup
 * directory. The only permitted files are the run's exact logfile and the exact
 * UUID-scoped set returned by the same glob contract as the files endpoint.
 */
function backupsheep_v2_backup_owns_file($file, $backup_uuid)
{
    $updraft = backupsheep_v2_updraftplus();
    if (is_wp_error($updraft)) {
        return $updraft;
    }

    $candidates = array((string) $updraft->get_logfile_name($backup_uuid));
    $matches = glob(rtrim($updraft->backups_dir_location(), '/\\') . '/*_' . $backup_uuid . '-*');
    if (is_array($matches)) {
        $candidates = array_merge($candidates, $matches);
    }

    foreach ($candidates as $candidate) {
        $candidate_path = realpath((string) $candidate);
        if (
            basename((string) $candidate) === $file['name']
            && $candidate_path !== false
            && $candidate_path === $file['path']
            && is_file($candidate_path)
        ) {
            return true;
        }
    }
    return false;
}

function backupsheep_v2_download(WP_REST_Request $request)
{
    $payload = backupsheep_v2_payload($request);
    $backup_uuid = backupsheep_v2_backup_uuid($payload);
    if (is_wp_error($backup_uuid)) {
        return $backup_uuid;
    }
    $file = backupsheep_v2_backup_file($payload);
    if (is_wp_error($file)) {
        return $file;
    }
    $owned = backupsheep_v2_backup_owns_file($file, $backup_uuid);
    if (is_wp_error($owned)) {
        return $owned;
    }
    if (!$owned) {
        return backupsheep_v2_file_not_found();
    }
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    nocache_headers();
    header('Content-Type: application/octet-stream');
    $stream = fopen($file['path'], 'rb');
    if ($stream === false) {
        status_header(500);
        exit;
    }
    $opened = fstat($stream);
    $current = lstat($file['path']);
    $resolved = realpath($file['path']);
    if (
        !is_array($opened)
        || !is_array($current)
        || $resolved === false
        || $resolved !== $file['path']
        || ($opened['mode'] & 0170000) !== 0100000
        || $opened['dev'] !== $current['dev']
        || $opened['ino'] !== $current['ino']
    ) {
        fclose($stream);
        status_header(409);
        exit;
    }
    header('Content-Disposition: attachment; filename="' . $file['name'] . '"');
    header('Content-Length: ' . (string) $opened['size']);
    header('X-Content-Type-Options: nosniff');
    fpassthru($stream);
    fclose($stream);
    exit;
}

function backupsheep_v2_delete(WP_REST_Request $request)
{
    $payload = backupsheep_v2_payload($request);
    $backup_uuid = backupsheep_v2_backup_uuid($payload);
    if (is_wp_error($backup_uuid)) {
        return $backup_uuid;
    }
    $file = backupsheep_v2_backup_file($payload);
    if (is_wp_error($file)) {
        if ($file->get_error_code() === 'backupsheep_v2_file_not_found') {
            return backupsheep_v2_response(array('deleted' => false));
        }
        return $file;
    }
    if (strpos($file['name'], '_' . $backup_uuid . '-') === false) {
        return new WP_Error(
            'backupsheep_v2_file_mismatch',
            __('The backup file does not belong to this backup.', 'backupsheep'),
            array('status' => 409)
        );
    }
    $deleted = unlink($file['path']);
    return backupsheep_v2_response(array('deleted' => (bool) $deleted));
}

function backupsheep_v2_rebuild_history()
{
    if (!class_exists('UpdraftPlus_Backup_History')) {
        return new WP_Error(
            'backupsheep_v2_history_unavailable',
            __('UpdraftPlus history is unavailable.', 'backupsheep'),
            array('status' => 503)
        );
    }
    UpdraftPlus_Backup_History::rebuild(false, false, false);
    return backupsheep_v2_response(array('rebuild_history' => true));
}

function backupsheep_v2_activate()
{
    $active = apply_filters('active_plugins', get_option('active_plugins', array()));
    if (!in_array('updraftplus/updraftplus.php', $active, true)) {
        wp_die(
            esc_html__('BackupSheep Secure Connector requires UpdraftPlus to be active.', 'backupsheep'),
            esc_html__('Plugin activation failed', 'backupsheep'),
            array('back_link' => true)
        );
    }

    // One-way safe migration from plugin v1.8. The v1 routes are absent from this file.
    $current = get_option(BACKUPSHEEP_V2_OPTION, array());
    $legacy = get_option('backupsheep_option_name', array());
    if (
        (!is_array($current) || empty($current['integration_secret']))
        && is_array($legacy)
        && isset($legacy['bs_wordpress_key_0'])
        && preg_match('/\A[A-Za-z0-9_-]{24,512}\z/D', (string) $legacy['bs_wordpress_key_0'])
    ) {
        update_option(
            BACKUPSHEEP_V2_OPTION,
            array('integration_secret' => (string) $legacy['bs_wordpress_key_0']),
            false
        );
        delete_option('backupsheep_option_name');
    }
    if (!wp_next_scheduled('backupsheep_v2_cleanup_nonces')) {
        wp_schedule_event(time() + 300, 'hourly', 'backupsheep_v2_cleanup_nonces');
    }
}
register_activation_hook(__FILE__, 'backupsheep_v2_activate');

function backupsheep_v2_deactivate()
{
    wp_clear_scheduled_hook('backupsheep_v2_cleanup_nonces');
}
register_deactivation_hook(__FILE__, 'backupsheep_v2_deactivate');

function backupsheep_v2_sanitize_options($input)
{
    $current = get_option(BACKUPSHEEP_V2_OPTION, array());
    $existing = is_array($current) && isset($current['integration_secret'])
        ? (string) $current['integration_secret']
        : '';
    $candidate = is_array($input) && isset($input['integration_secret'])
        ? trim((string) $input['integration_secret'])
        : '';
    if ($candidate === '') {
        return array('integration_secret' => $existing);
    }
    if (!preg_match('/\A[A-Za-z0-9_-]{24,512}\z/D', $candidate)) {
        add_settings_error(
            BACKUPSHEEP_V2_OPTION,
            'invalid_secret',
            __('The integration key must be a 24-512 character URL-safe token.', 'backupsheep')
        );
        return array('integration_secret' => $existing);
    }
    return array('integration_secret' => $candidate);
}

function backupsheep_v2_admin_init()
{
    register_setting(
        'backupsheep_v2_group',
        BACKUPSHEEP_V2_OPTION,
        array('sanitize_callback' => 'backupsheep_v2_sanitize_options')
    );
    add_settings_section(
        'backupsheep_v2_section',
        __('Secure connector', 'backupsheep'),
        '__return_false',
        'backupsheep-v2'
    );
    add_settings_field(
        'backupsheep_v2_secret',
        __('WordPress integration key', 'backupsheep'),
        'backupsheep_v2_secret_field',
        'backupsheep-v2',
        'backupsheep_v2_section'
    );
}
add_action('admin_init', 'backupsheep_v2_admin_init');

function backupsheep_v2_secret_field()
{
    $configured = backupsheep_v2_secret() !== '';
    echo '<input class="regular-text" type="password" autocomplete="new-password" name="'
        . esc_attr(BACKUPSHEEP_V2_OPTION)
        . '[integration_secret]" value="" placeholder="'
        . esc_attr($configured ? __('Leave blank to keep the current key', 'backupsheep') : '')
        . '">';
    if ($configured) {
        echo '<p class="description">'
            . esc_html__('A key is configured. It is never displayed by this plugin.', 'backupsheep')
            . '</p>';
    }
}

function backupsheep_v2_admin_menu()
{
    add_options_page(
        __('BackupSheep', 'backupsheep'),
        __('BackupSheep', 'backupsheep'),
        'manage_options',
        'backupsheep-v2',
        'backupsheep_v2_admin_page'
    );
}
add_action('admin_menu', 'backupsheep_v2_admin_menu');

function backupsheep_v2_admin_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }
    echo '<div class="wrap"><h1>' . esc_html__('BackupSheep Secure Connector', 'backupsheep') . '</h1>';
    echo '<p>' . esc_html__('Paste the integration key generated by your BackupSheep installation.', 'backupsheep') . '</p>';
    settings_errors(BACKUPSHEEP_V2_OPTION);
    echo '<form method="post" action="options.php">';
    settings_fields('backupsheep_v2_group');
    do_settings_sections('backupsheep-v2');
    submit_button();
    echo '</form></div>';
}
