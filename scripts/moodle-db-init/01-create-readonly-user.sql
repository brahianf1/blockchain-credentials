-- Crear usuario de solo lectura para el portal de credenciales.
-- Este script se ejecuta automaticamente en la primera inicializacion del contenedor.
-- Para instancias existentes, ejecutar manualmente via:
--   docker exec moodle-db psql -U moodle_user -d moodle_db -f /docker-entrypoint-initdb.d/01-create-readonly-user.sql

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'moodle_readonly') THEN
        CREATE ROLE moodle_readonly WITH LOGIN PASSWORD 'W2V9Wg2Y5KHJR5HVhRKslqSWFBTW6Zo3';
    END IF;
END
$$;

GRANT CONNECT ON DATABASE moodle_db TO moodle_readonly;
GRANT USAGE ON SCHEMA public TO moodle_readonly;
GRANT SELECT ON mdl_user TO moodle_readonly;
GRANT SELECT ON mdl_course TO moodle_readonly;
GRANT SELECT ON mdl_block_credenciales TO moodle_readonly;
GRANT SELECT ON mdl_block_credenciales_logs TO moodle_readonly;
GRANT SELECT ON mdl_course_completions TO moodle_readonly;
GRANT SELECT ON mdl_grade_grades TO moodle_readonly;
GRANT SELECT ON mdl_grade_items TO moodle_readonly;
