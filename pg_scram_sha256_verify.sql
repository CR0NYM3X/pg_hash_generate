/*
 @Function: public.pg_scram_sha256_verify
 @Creation Date: 09/02/2026
 @Description: Valida si una contraseña en texto plano coincide con un hash SCRAM-SHA-256.
-  validación estricta de StoredKey y ServerKey.
 @Parameters:
   - @p_password (text): Contraseña ingresada por el usuario.
   - @p_stored_hash (text): Hash completo guardado en la DB (formato SCRAM-SHA-256$...).
 @Returns: boolean - TRUE si la contraseña es correcta, FALSE de lo contrario.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 09/02/2026
 @Change: Creación inicial siguiendo el estándar RFC 7677.
 @Author: CR0NYM3X
*/

create EXTENSION pgcrypto ;

-- DROP FUNCTION public.pg_scram_sha256_verify(text, text);
CREATE OR REPLACE FUNCTION public.pg_scram_sha256_verify(
    p_password    text, 
    p_stored_hash text
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $func$
DECLARE
    v_parts           text[];
    v_iters_salt      text[];
    v_keys            text[];
    
    v_iterations      integer;
    v_salt_bin        bytea;
    v_stored_key_db   text;
    v_server_key_db   text;
    
    v_salted_pw       bytea;
    v_client_key      bytea;
    v_server_key_calc bytea;
    v_stored_key_calc bytea;
    
    v_u               bytea;
    v_t               bytea;
    v_i integer; v_j integer;
BEGIN
    -- 1. Split estricto
    v_parts      := string_to_array(p_stored_hash, '$');
    IF array_length(v_parts, 1) <> 3 THEN RETURN FALSE; END IF;

    v_iters_salt := string_to_array(v_parts[2], ':');
    v_keys       := string_to_array(v_parts[3], ':');
    
    -- Validar que existan todas las partes
    IF array_length(v_iters_salt, 1) <> 2 OR array_length(v_keys, 1) <> 2 THEN 
        RETURN FALSE; 
    END IF;

    v_iterations    := v_iters_salt[1]::integer;
    v_salt_bin      := decode(v_iters_salt[2], 'base64');
    v_stored_key_db := v_keys[1];
    v_server_key_db := v_keys[2]; -- La que estabas alterando

    -- 2. Cálculo de PBKDF2
    v_u := public.hmac(v_salt_bin || E'\\x00000001'::bytea, p_password::bytea, 'sha256');
    v_t := v_u; 
    FOR v_i IN 2..v_iterations LOOP
        v_u := public.hmac(v_u, p_password::bytea, 'sha256');
        FOR v_j IN 0..31 LOOP
            v_t := set_byte(v_t, v_j, get_byte(v_t, v_j) # get_byte(v_u, v_j));
        END LOOP;
    END LOOP;
    v_salted_pw := v_t;

    -- 3. Calcular AMBAS llaves para validación total
    v_client_key      := public.hmac('Client Key'::bytea, v_salted_pw, 'sha256');
    v_stored_key_calc := public.digest(v_client_key, 'sha256');
    v_server_key_calc := public.hmac('Server Key'::bytea, v_salted_pw, 'sha256');

    -- 4. Comparación estricta (usando regexp_replace para limpiar el b64 calculado)
    -- Si la ServerKey o StoredKey de la DB tienen "TEXT_EXTRA", esto devolverá FALSE.
    RETURN (v_stored_key_db = regexp_replace(encode(v_stored_key_calc, 'base64'), E'\\s', '', 'g'))
       AND (v_server_key_db = regexp_replace(encode(v_server_key_calc, 'base64'), E'\\s', '', 'g'));

EXCEPTION
    WHEN OTHERS THEN RETURN FALSE;
END;
$func$;


---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_scram_sha256_verify(text, text) IS
'Verifica contraseñas contra hashes SCRAM-SHA-256.
- Parámetros: p_password (input), p_stored_hash (hash de la DB).
- Retorno: boolean.
- Seguridad: SECURITY INVOKER.
- Notas: Extrae automáticamente salt e iteraciones del hash.';


ALTER FUNCTION public.pg_scram_sha256_verify(text, text) SET search_path TO public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.pg_scram_sha256_verify(text, text) FROM PUBLIC;


-- select * from public.pg_scram_sha256_verify('password123', 'SCRAM-SHA-256$10000:vk2Y3Dp2jD6XCdcI3cqmMQ==$2J2PAu6w1rOBiy+F5JOjY3i94ZIpYGCKfkSphzf6RBk=:gDctN/Chn0if2DlAWKTl5X9JBX89KZzMSk1TIcrs9HI=');



