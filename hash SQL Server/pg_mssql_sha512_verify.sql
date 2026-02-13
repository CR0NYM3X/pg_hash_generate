CREATE OR REPLACE FUNCTION text_to_utf16le(txt text) 
RETURNS bytea AS $$
BEGIN
    -- Convierte el texto a bytes y añade un byte nulo (\x00) después de cada carácter
    RETURN decode(regexp_replace(encode(txt::bytea, 'hex'), '(..)', '\100', 'g'), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;





CREATE OR REPLACE FUNCTION pg_mssql_sha512_verify(password_plain text, password_hash_input text)
RETURNS boolean AS $$
DECLARE
    password_hash bytea;
    salt bytea;
    password_utf16le bytea;
    recomputed_hash bytea;
    header bytea;
BEGIN
    -- 1. Convertir entrada hex a bytea
    IF password_hash_input LIKE '0x%' THEN
        password_hash := decode(substring(password_hash_input from 3), 'hex');
    ELSE
        password_hash := decode(password_hash_input, 'hex');
    END IF;

    -- 2. Extraer Header (2 bytes) y Salt (4 bytes)
    header := substring(password_hash from 1 for 2);
    salt := substring(password_hash from 3 for 4);

    -- 3. Convertir contraseña a UTF-16LE
    password_utf16le := text_to_utf16le(password_plain);

    -- 4. Validar según versión 
    -- 0x0200 utiliza SHA-512 según el estándar de SQL Server 2012+
    IF header = decode('0200', 'hex') THEN
        recomputed_hash := digest(password_utf16le || salt, 'sha512');
    ELSIF header = decode('0100', 'hex') THEN
        recomputed_hash := digest(password_utf16le || salt, 'sha1');
    ELSE
        RETURN FALSE;
    END IF;

    -- 5. Comparar con el cuerpo del hash (empezando en el byte 7)
    RETURN recomputed_hash = substring(password_hash from 7);
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION pg_mssql_sha512_generate(password text)
RETURNS text AS $$
DECLARE
    salt bytea;
    password_utf16le bytea;
    hashed_part bytea;
    final_hash bytea;
BEGIN
    salt := gen_random_bytes(4);
    password_utf16le := text_to_utf16le(password);
    
    -- SQL Server 2012+ usa SHA-512
    hashed_part := digest(password_utf16le || salt, 'sha512');
    
    final_hash := decode('0200', 'hex') || salt || hashed_part;
    
    RETURN '0x' || upper(encode(final_hash, 'hex'));
END;
$$ LANGUAGE plpgsql;


-- SELECT pg_mssql_sha512_verify(
--    'Test123', 
--    '0x020014CEB03EA4671C2F62F7BDDA17123C4AA58113FC85E755FF80030E352DF5CFCE7CD8DC241191D86B37E244424F053AB2D9E768721D29B13B22118777B65CE9E5F6D79C10'
-- );

