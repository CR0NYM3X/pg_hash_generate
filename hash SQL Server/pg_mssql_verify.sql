
/*
 @Function: public.pg_mssql_verify
 @Creation Date: 15/02/2026
 @Description: Verifica una contraseña contra hashes de SQL Server (0x0100 y 0x0200).
                Retorna metadatos detallados del proceso de validación.
 @Parameters:
   - @p_password_plain (text): Contraseña en texto plano a verificar.
   - @p_password_hash_input (text): Hash almacenado (ej. '0x0200...')
 @Returns: TABLE - (is_valid, version, algorithm, salt, computed_hash)
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 15/02/2026
 @Change: Estandarización corporativa, retorno tipo TABLE y blindaje de esquemas.
 @Author: CR0NYM3X
*/

---------------- CODE ----------------
-- DROP FUNCTION public.pg_mssql_verify(text,text);

CREATE OR REPLACE FUNCTION public.pg_mssql_verify(
    p_password_plain text, 
    p_password_hash_input text
)
RETURNS TABLE (
    is_valid      boolean,
    algorithm     text,
    version       text,
    salt          text
    --,computed_hash text
) 
AS $func$
DECLARE
    -- Variables internas de procesamiento binario
    v_password_hash    bytea;
    v_salt_bytea       bytea;
    v_pwd_utf16le      bytea;
    v_recomputed_bytea bytea;
    v_header_bytea     bytea;
    v_stored_hash_part bytea;
BEGIN
    -- Inicialización de valores de retorno (Default: Fallo)
    is_valid      := FALSE;
    version       := 'UNKNOWN';
    algorithm     := 'UNKNOWN';
    salt          := NULL;
    --computed_hash := NULL;

    -- 1. Normalización y Decodificación Hexadecimal
    -- Se usa pg_catalog explícitamente y comas en substring para evitar errores de sintaxis
    BEGIN
        IF p_password_hash_input LIKE '0x%' THEN
            v_password_hash := pg_catalog.decode(pg_catalog.substring(p_password_hash_input, 3), 'hex');
        ELSE
            v_password_hash := pg_catalog.decode(p_password_hash_input, 'hex');
        END IF;
    EXCEPTION WHEN OTHERS THEN
        -- Si el hash de entrada es inválido, retornamos la fila con los valores default
        RETURN NEXT;
        RETURN;
    END;

    -- 2. Extracción de Metadatos del Binario
    -- Header: primeros 2 bytes | Salt: siguientes 4 bytes
    v_header_bytea := pg_catalog.substring(v_password_hash, 1, 2);
    v_salt_bytea   := pg_catalog.substring(v_password_hash, 3, 4);
    
    -- Formatear salt para la salida informativa
    salt := '0x' || pg_catalog.upper(pg_catalog.encode(v_salt_bytea, 'hex'));

    -- 3. Identificación de Lógica según Versión (Header)
    IF v_header_bytea = pg_catalog.decode('0200', 'hex') THEN
        version   := '0x0200';
        algorithm := 'sha512';
    ELSIF v_header_bytea = pg_catalog.decode('0100', 'hex') THEN
        version   := '0x0100';
        algorithm := 'sha1';
    ELSE
        -- Si el header no coincide con estándares MSSQL
        RETURN NEXT;
        RETURN;
    END IF;

    -- 4. Re-generación del Hash para Comparación
    -- Importante: Invocamos el helper de UTF16LE y digest de pgcrypto
    v_pwd_utf16le      := public.text_to_utf16le(p_password_plain);
    v_recomputed_bytea := public.digest(v_pwd_utf16le || v_salt_bytea, algorithm);
    
    -- 5. Preparación de Resultados Finales
    -- El hash real en el binario de MSSQL inicia en el byte 7
    v_stored_hash_part := pg_catalog.substring(v_password_hash, 7);
    -- computed_hash      := '0x' || pg_catalog.upper(pg_catalog.encode(v_recomputed_bytea, 'hex'));
    
    -- Comparación binaria final
    is_valid := (v_recomputed_bytea = v_stored_hash_part);

    -- Actualizar algoritmo para la salida (formato estético)
    algorithm := pg_catalog.upper(algorithm);

    RETURN NEXT;
END;
$func$ 
LANGUAGE plpgsql 
STABLE
STRICT
SECURITY DEFINER;

-- Endurecimiento de Seguridad
ALTER FUNCTION public.pg_mssql_verify(text, text) 
SET search_path TO public, pg_temp;

-- Revocar permisos públicos por defecto
REVOKE EXECUTE ON FUNCTION public.pg_mssql_verify(text, text) FROM PUBLIC;


---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_mssql_verify(text, text) IS
'Verificador de integridad de credenciales MSSQL.
- Retorno: Registro con resultado booleano y desglose técnico del hash.
- Algoritmos: Detecta SHA-1 (Legacy) y SHA-512 (Modern).
- Seguridad: SECURITY DEFINER con search_path restringido.';


--  SHA-1 Legacy <= 2008
-- SELECT * FROM public.pg_mssql_verify('admin123', '0x01003667CAD7199125862BFB8B6A1593920D8A023607EF8E2C34');

--  SHA-512 >= 2012
-- SELECT * FROM public.pg_mssql_verify('admin123', '0x0200A894AC7FE5A69BF12B4A0FA57301D12A0EB6B6C59B8663EF916FC92E7DA2EF05FD07E687EAA1B68EA3F6CAF59219EB708EFB788AF2F8B61F79135B07FB4A33F35D8280E1');

 
