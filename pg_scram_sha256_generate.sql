
/*
 @Function: public.pg_scram_sha256_generate
 @Creation Date: 09/02/2026
 @Description: Genera hash SCRAM-SHA-256 y retorna sus componentes desglosados en formato tabla.
    - IMPLEMENTACIÓN COMPLETA Y CORRECTA CON PBKDF2 REAL
    - Esta es la versión más precisa que sigue el estándar RFC 7677
 @Parameters:
   - @p_password (text): Contraseña en texto plano.
   - @p_iterations (integer): Iteraciones para el algoritmo PBKDF2.
 @Returns: TABLE (hash, algoritmo, iteraciones, salt, stored_key, server_key)
 @Author: CR0NYM3X

 ---------------- HISTORY ----------------
 @Date: 09/02/2026
 @Author: CR0NYM3X
*/


---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_scram_sha256_generate(text, integer) IS
'Genera componentes SCRAM-SHA-256 detallados.
- Parámetros: p_password, p_iterations.
- Retorno: TABLE con desglose técnico del hash.
- Volatilidad: VOLATILE.
- Seguridad: SECURITY INVOKER con search_path protegido.';




CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- DROP FUNCTION public.pg_scram_sha256_generate(text, integer);

CREATE OR REPLACE FUNCTION public.pg_scram_sha256_generate(
    p_password   text, 
    p_iterations integer DEFAULT 4096
)
RETURNS TABLE (
    hash        text,
    algoritmo   text,
    iteraciones integer,
    salt        text,
    stored_key  text,
    server_key  text
)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
AS $func$
DECLARE
    -- Variables locales (Prefijo v_)
    v_salt           bytea;
    v_salted_pw      bytea;
    v_client_key     bytea;
    v_stored_key_bin bytea;
    v_server_key_bin bytea;
    
    -- Variables para PBKDF2
    v_u              bytea;
    v_t              bytea;
    
    -- Variables de salida string
    v_salt_b64       text;
    v_stored_key_b64 text;
    v_server_key_b64 text;
    v_hash_final     text;
    
    -- Iteradores
    v_i              integer;
    v_j              integer;
BEGIN
    -- 1. Validaciones
    IF p_password IS NULL OR length(trim(p_password)) = 0 THEN
        RAISE EXCEPTION 'ERR-VAL: La contraseña no puede ser nula o vacía.';
    END IF;
    
    IF p_iterations < 1 THEN
        RAISE EXCEPTION 'ERR-VAL: Las iteraciones deben ser mayores a 0.';
    END IF;

    -- 2. Generar salt aleatorio
    v_salt := public.gen_random_bytes(16);
    
    -- 3. PBKDF2 con HMAC-SHA256
    v_u := public.hmac(v_salt || E'\\x00000001'::bytea, p_password::bytea, 'sha256');
    v_t := v_u; 
    
    FOR v_i IN 2..p_iterations LOOP
        v_u := public.hmac(v_u, p_password::bytea, 'sha256');
        FOR v_j IN 0..31 LOOP
            v_t := set_byte(v_t, v_j, get_byte(v_t, v_j) # get_byte(v_u, v_j));
        END LOOP;
    END LOOP;
    
    v_salted_pw := v_t;
    
    -- 4. Derivación de llaves SCRAM
    -- ClientKey = HMAC(SaltedPassword, "Client Key")
    v_client_key     := public.hmac('Client Key'::bytea, v_salted_pw, 'sha256');
    -- StoredKey = SHA256(ClientKey)
    v_stored_key_bin := public.digest(v_client_key, 'sha256');
    -- ServerKey = HMAC(SaltedPassword, "Server Key")
    v_server_key_bin := public.hmac('Server Key'::bytea, v_salted_pw, 'sha256');
    
    -- 5. Encoding Base64 y Limpieza sin saltos de línea
    -- E'\\s' captura cualquier espacio en blanco, incluyendo saltos de línea del encoding base64
    v_salt_b64       := regexp_replace(encode(v_salt, 'base64'), E'\\s', '', 'g');
    v_stored_key_b64 := regexp_replace(encode(v_stored_key_bin, 'base64'), E'\\s', '', 'g');
    v_server_key_b64 := regexp_replace(encode(v_server_key_bin, 'base64'), E'\\s', '', 'g');

    -- 6. Construcción del Hash Completo
    v_hash_final := format('SCRAM-SHA-256$%s:%s$%s:%s', 
                           p_iterations, v_salt_b64, v_stored_key_b64, v_server_key_b64);

    -- 7. Retorno de resultados
    RETURN QUERY 
    SELECT 
        v_hash_final,
        'SCRAM-SHA-256'::text,
        p_iterations,
        v_salt_b64,
        v_stored_key_b64,
        v_server_key_b64;
END;
$func$;



-- Seguridad: Fija search_path
ALTER FUNCTION public.pg_scram_sha256_generate(text, integer) SET search_path TO public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.pg_scram_sha256_generate(text, integer) FROM PUBLIC;
 

