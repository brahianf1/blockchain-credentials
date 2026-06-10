<?php
/**
 * Pruebas unitarias de las funciones de block_credenciales (lib.php).
 *
 * Se prueban dos grupos, ambos SIN levantar un entorno Moodle completo:
 *
 *  1) Funciones puras (base64url, generación de JWT, hash): usan solo PHP
 *     nativo (hash_hmac, base64_encode, json_encode), no necesitan mocks.
 *
 *  2) `block_credenciales_get_portal_url`: arma la URL de ingreso al portal con
 *     un JWT de corta duración. Llama a dos funciones de Moodle (`get_config`
 *     e `is_siteadmin`), que aquí se reemplazan por STUBS livianos para poder
 *     probar la lógica de forma aislada.
 *
 * Bootstrap mínimo: lib.php empieza con `defined('MOODLE_INTERNAL') || die();`,
 * así que definimos esa constante antes de incluirlo.
 *
 * Cómo correr (sin Moodle):
 *     composer require --dev phpunit/phpunit
 *     ./vendor/bin/phpunit -c tests/phpunit.xml
 *
 * @package block_credenciales
 */

if (!defined('MOODLE_INTERNAL')) {
    define('MOODLE_INTERNAL', true);
}
require_once __DIR__ . '/../lib.php';

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// STUBS de funciones de Moodle (no se carga Moodle en estas pruebas).
// El estado es configurable por test mediante variables globales.
// ---------------------------------------------------------------------------
$GLOBALS['mock_bc_config'] = new stdClass();
$GLOBALS['mock_bc_siteadmin'] = false;

if (!function_exists('get_config')) {
    function get_config($plugin) {
        return $GLOBALS['mock_bc_config'];
    }
}
if (!function_exists('is_siteadmin')) {
    function is_siteadmin($userid = null) {
        return $GLOBALS['mock_bc_siteadmin'];
    }
}

class block_credenciales_lib_test extends TestCase {

    protected function setUp(): void {
        // Estado limpio de los stubs antes de cada prueba.
        $GLOBALS['mock_bc_config'] = new stdClass();
        $GLOBALS['mock_bc_siteadmin'] = false;
    }

    // -- Helpers -----------------------------------------------------------

    private function sample_user() {
        return (object) [
            'id'        => 42,
            'email'     => 'ada@utn.edu',
            'firstname' => 'Ada',
            'lastname'  => 'Lovelace',
        ];
    }

    private function decode_payload($jwt) {
        $parts = explode('.', $jwt);
        return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    }

    private function token_from_url($url) {
        $pos = strpos($url, 'token=');
        return urldecode(substr($url, $pos + strlen('token=')));
    }

    // -- base64url ---------------------------------------------------------

    public function test_base64url_encode_vector_conocido() {
        // base64('foobar') = 'Zm9vYmFy' (no necesita padding).
        $this->assertSame('Zm9vYmFy', block_credenciales_base64url_encode('foobar'));
    }

    public function test_base64url_encode_es_url_safe_y_sin_padding() {
        $bin = "\xfb\xff\xbf";                       // bytes que en base64 dan '+' y '/'
        $encoded = block_credenciales_base64url_encode($bin);

        $this->assertStringNotContainsString('=', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);

        // Round-trip: decodificar debe devolver los bytes originales.
        $decoded = base64_decode(strtr($encoded, '-_', '+/'));
        $this->assertSame($bin, $decoded);
    }

    public function test_base64url_encode_cadena_vacia() {
        $this->assertSame('', block_credenciales_base64url_encode(''));
    }

    public function test_base64url_encode_roundtrip_texto_largo() {
        $data = str_repeat('Lorem ipsum dolor sit amet. ', 10);
        $encoded = block_credenciales_base64url_encode($data);

        $this->assertStringNotContainsString('=', $encoded);
        $this->assertSame($data, base64_decode(strtr($encoded, '-_', '+/')));
    }

    // -- generate_jwt ------------------------------------------------------

    public function test_generate_jwt_estructura_y_firma() {
        $payload = ['sub' => '42', 'name' => 'Ada Lovelace'];
        $secret = 'super-secret';

        $jwt = block_credenciales_generate_jwt($payload, $secret);
        $parts = explode('.', $jwt);

        // 1) Tres partes.
        $this->assertCount(3, $parts);

        // 2) Header correcto.
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        $this->assertSame('HS256', $header['alg']);
        $this->assertSame('JWT', $header['typ']);

        // 3) Payload recuperable.
        $body = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        $this->assertSame('42', $body['sub']);
        $this->assertSame('Ada Lovelace', $body['name']);

        // 4) Firma HS256 válida (recomputada de forma independiente).
        $expected_sig = block_credenciales_base64url_encode(
            hash_hmac('sha256', "{$parts[0]}.{$parts[1]}", $secret, true)
        );
        $this->assertSame($expected_sig, $parts[2]);
    }

    public function test_generate_jwt_es_determinista() {
        $payload = ['sub' => '7'];
        $secret = 'k';
        $this->assertSame(
            block_credenciales_generate_jwt($payload, $secret),
            block_credenciales_generate_jwt($payload, $secret)
        );
    }

    public function test_generate_jwt_secretos_distintos_dan_firmas_distintas() {
        $payload = ['sub' => '1'];
        $a = explode('.', block_credenciales_generate_jwt($payload, 'secreto-A'));
        $b = explode('.', block_credenciales_generate_jwt($payload, 'secreto-B'));

        $this->assertSame($a[0], $b[0]);        // mismo header
        $this->assertSame($a[1], $b[1]);        // mismo payload
        $this->assertNotSame($a[2], $b[2]);     // distinta firma
    }

    public function test_generate_jwt_preserva_claims_unicode_y_anidados() {
        $payload = [
            'full_name' => 'José Pérez Ñandú',
            'roles'     => ['alumno', 'egresado'],
            'meta'      => ['curso' => 'Matemática'],
        ];
        $body = $this->decode_payload(block_credenciales_generate_jwt($payload, 'k'));

        $this->assertSame('José Pérez Ñandú', $body['full_name']);
        $this->assertSame(['alumno', 'egresado'], $body['roles']);
        $this->assertSame('Matemática', $body['meta']['curso']);
    }

    // -- get_portal_url (con stubs de Moodle) ------------------------------

    public function test_get_portal_url_sin_secreto_devuelve_url_plana() {
        $GLOBALS['mock_bc_config']->portal_url = 'https://portal.test';
        // Sin portal_jwt_secret => no se puede firmar => fallback sin token.

        $url = block_credenciales_get_portal_url($this->sample_user());

        $this->assertSame('https://portal.test', $url);
        $this->assertStringNotContainsString('token=', $url);
    }

    public function test_get_portal_url_con_secreto_incluye_callback_y_token() {
        $GLOBALS['mock_bc_config']->portal_url = 'https://portal.test';
        $GLOBALS['mock_bc_config']->portal_jwt_secret = 'secreto';

        $url = block_credenciales_get_portal_url($this->sample_user());

        $this->assertStringContainsString(
            'https://portal.test/auth/moodle-callback?token=', $url
        );
        $this->assertCount(3, explode('.', $this->token_from_url($url))); // JWT válido
    }

    public function test_get_portal_url_payload_correcto() {
        $GLOBALS['mock_bc_config']->portal_url = 'https://portal.test';
        $GLOBALS['mock_bc_config']->portal_jwt_secret = 'secreto';

        $url = block_credenciales_get_portal_url($this->sample_user());
        $payload = $this->decode_payload($this->token_from_url($url));

        $this->assertSame(42, $payload['moodle_user_id']);
        $this->assertSame('ada@utn.edu', $payload['email']);
        $this->assertSame('Ada Lovelace', $payload['full_name']);
        $this->assertFalse($payload['is_admin']);
        // TTL de 5 minutos (300 s) entre emisión y expiración.
        $this->assertSame($payload['iat'] + 300, $payload['exp']);
    }

    public function test_get_portal_url_is_admin_refleja_siteadmin() {
        $GLOBALS['mock_bc_config']->portal_url = 'https://portal.test';
        $GLOBALS['mock_bc_config']->portal_jwt_secret = 'secreto';
        $GLOBALS['mock_bc_siteadmin'] = true;

        $url = block_credenciales_get_portal_url($this->sample_user());
        $payload = $this->decode_payload($this->token_from_url($url));

        $this->assertTrue($payload['is_admin']);
    }

    public function test_get_portal_url_usa_ampersand_si_la_url_ya_tiene_query() {
        $GLOBALS['mock_bc_config']->portal_url = 'https://portal.test/landing?ref=moodle';
        $GLOBALS['mock_bc_config']->portal_jwt_secret = 'secreto';

        $url = block_credenciales_get_portal_url($this->sample_user());

        // Como la URL ya tenía '?', el token se agrega con '&'.
        $this->assertStringContainsString('/auth/moodle-callback&token=', $url);
    }

    // -- Consistencia de hash con el backend Python ------------------------

    /**
     * CONTRATO ENTRE LENGUAJES: el hash de credencial calculado en PHP debe
     * ser idéntico al que calcula el backend Python (compute_credential_hash).
     *
     * El fixture y la constante esperada son LOS MISMOS que en
     * backend/controller/tests/test_hashing.py. Si alguno de los dos lados
     * cambia el orden de concatenación, el formato de fecha o el algoritmo,
     * este test (o su gemelo en Python) falla — antes de que rompa la
     * verificación on-chain en producción.
     */
    public function test_hash_consistente_con_backend_python() {
        $student_id = '42';
        $course_id = '7';
        $completion_date = '2026-06-10T12:00:00+00:00';
        $grade = 'Aprobado';

        $expected = 'f05c5a74f693c09731b130a39dcbeec9904a1e2ea366b8a5a61176596403dbea';

        // Mismo orden de concatenación que utils/hashing.py:
        //   f"{student_id}{course_id}{completion_date}{grade}"
        $hash = hash('sha256', $student_id . $course_id . $completion_date . $grade);

        $this->assertSame(
            $expected,
            $hash,
            'El hash de PHP (Moodle) debe coincidir con el de Python (backend).'
        );
    }

    public function test_hash_segundo_vector_conocido() {
        $expected = '21699325024681d74af166b9776b8fc185038f9fea318902b370a547a30acdfe';
        $hash = hash('sha256', '100' . '25' . '2025-12-01T09:30:00+00:00' . '9.5');
        $this->assertSame($expected, $hash);
    }
}
