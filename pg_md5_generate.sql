/*
 @Function: public.pg_md5_generate
 @Creation Date: 09/02/2026
 @Description: Genera un hash MD5 compatible con el formato legacy de PostgreSQL (md5 + hash).
 @Parameters:
   - @p_password (text): Contraseña en texto plano.
   - @p_username (text): Nombre del rol/usuario (se usa como salt en MD5).
 @Returns: text - String con prefijo 'md5' seguido del hash hexadecimal.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 09/02/2026
 @Change: Estandarización a plantilla corporativa y nomenclatura p_/v_.
 @Author: CR0NYM3X
*/

 
/*

IMPORTANTE: 
- MD5 está DEPRECADO desde PostgreSQL 10
- Se recomienda usar SCRAM-SHA-256 en su lugar
- Esta función es para compatibilidad con sistemas legacy
- NO usar para nuevos desarrollos

Formato MD5 de PostgreSQL:
md5<hash_hexadecimal>

donde hash_hexadecimal = md5(password + username)
*/



 -- DROP  FUNCTION public.pg_md5_generate(text,text);
CREATE OR REPLACE FUNCTION public.pg_md5_generate(
    p_username text,
    p_password text
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SECURITY INVOKER
AS $func$
DECLARE
    -- Variables locales (v_)
    v_hash_hex text;
BEGIN
    -- 1. Validaciones de entrada
    IF p_password IS NULL OR length(trim(p_password)) = 0 THEN
        RAISE EXCEPTION 'ERR-VAL: La contraseña no puede ser nula o vacía.';
    END IF;

    IF p_username IS NULL OR length(trim(p_username)) = 0 THEN
        RAISE EXCEPTION 'ERR-VAL: El nombre de usuario no puede ser nulo o vacío.';
    END IF;

    -- 2. Generar hash MD5 (Concatenación estándar de Postgres)
    v_hash_hex := pg_catalog.md5(p_password || p_username);

    -- 3. Retornar con prefijo 'md5'
    RETURN 'md5' || v_hash_hex;

EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'ERR-INTERNAL: Error al generar MD5. Detalle: %', SQLERRM;
END;
$func$;



---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_md5_generate(text, text) IS
'Genera hashes MD5 siguiendo el formato tradicional de PostgreSQL.
- Parámetros: p_password, p_username.
- Retorno: text (md5 + hash_hex).
- Volatilidad: IMMUTABLE.
- Seguridad: SECURITY INVOKER con search_path protegido.
- Notas: Formato compatible con pg_authid en versiones legacy o configuraciones md5.';


-- Seguridad: Fija search_path
ALTER FUNCTION public.pg_md5_generate(text, text) SET search_path TO public, pg_temp;

---------------- SECURITY REVOKE ----------------
REVOKE EXECUTE ON FUNCTION public.pg_md5_generate(text, text) FROM PUBLIC;

 
-- SELECT * from public.pg_md5_generate( 'user_test', 'password123') AS hash_md5; --> md5a55cc73725a729b561ecfc4984d922a9


