



---------------- EXAMPLE USAGE ----------------
-- 1. Eliminar función previa (limpieza)
-- DROP FUNCTION IF EXISTS public.pg_scram_sha256_generate(text, integer);

-- 2. Generar hash estándar (4096 iters)
SELECT * from  public.pg_scram_sha256_generate('password123');

-- 3. Generar hash con alta seguridad (10,000 iters)
SELECT * from  public.pg_scram_sha256_generate('password123', 10000);

-- 4. Probar validación de error
-- SELECT * from  public.pg_scram_sha256_generate('', 0);


---------------- EJEMPLO CON FUNCION ANONIMA ----------------

DO $script_test$
DECLARE
    -- Parámetros (p_)
    p_usuario_objetivo text    := 'user_test';
    p_password_nuevo   text    := 'password123';
    p_iteraciones      integer := 4096;

    -- Variables locales (v_)
    v_resultado_hash       text;
    v_resultado_algoritmo  text;
    v_resultado_iters      integer;
    v_resultado_salt       text;
    v_resultado_stored_key text;
    v_resultado_server_key text;
    
    -- Variables de control
    v_sql_comando          text;
    v_usuario_existe       boolean;
BEGIN
     SET client_min_messages = 'notice' ; 

    -- 1. Generación de componentes mediante la función de tabla
    SELECT hash, algoritmo, iteraciones, salt, stored_key, server_key
      INTO v_resultado_hash, v_resultado_algoritmo, v_resultado_iters, 
           v_resultado_salt, v_resultado_stored_key, v_resultado_server_key
    FROM public.pg_scram_sha256_generate(p_password_nuevo, p_iteraciones);

    -- 2. Impresión de resultados (Formato solicitado)
    RAISE NOTICE '========== TEST SCRAM-SHA-256 ==========';
    RAISE NOTICE 'Algoritmo    : %', v_resultado_algoritmo;
    RAISE NOTICE 'Iteraciones  : %', v_resultado_iters;
    RAISE NOTICE 'Salt (B64)   : %', v_resultado_salt;
    RAISE NOTICE 'Stored Key   : %', v_resultado_stored_key;
    RAISE NOTICE 'Server Key   : %', v_resultado_server_key;
    RAISE NOTICE '----------------------------------------';
    RAISE NOTICE 'HASH COMPLETO: %', v_resultado_hash;
    RAISE NOTICE '========================================';

    -- 3. Lógica de creación/actualización idempotente
    SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = p_usuario_objetivo) 
      INTO v_usuario_existe;

    IF NOT v_usuario_existe THEN
        -- Crear usuario si no existe
        v_sql_comando := format('CREATE USER %I WITH PASSWORD %L', p_usuario_objetivo, v_resultado_hash);
        EXECUTE v_sql_comando;
        RAISE NOTICE 'PROCESO: Usuario "%" creado exitosamente con el hash generado.', p_usuario_objetivo;
    ELSE
        -- Solo actualizar si ya existe
        v_sql_comando := format('ALTER USER %I WITH PASSWORD %L', p_usuario_objetivo, v_resultado_hash);
        EXECUTE v_sql_comando;
        RAISE NOTICE 'PROCESO: Usuario "%" ya existía. Contraseña actualizada.', p_usuario_objetivo;
    END IF;

EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'ERROR EN SCRIPT: %', SQLERRM;
END $script_test$;


---------------------- Hacer pruebas  ---------------------- 

select usename,passwd from pg_shadow  where usename = 'user_test';
\q
PGPASSWORD='password123' psql -h 127.0.0.1 -p 5432 -d postgres -U user_test



---------------------- Validar -----------------------


select * from public.pg_verify_scram_sha256('password123', 'SCRAM-SHA-256$10000:BfjFRQ5cJh8ORscTYOuwuQ==$5a5hkxA6mouSmmCl4m0yd/klStxHVBLp8dLTPbRwLj4=:VuswwU3Muvs2p1q0Oxu7P7rhk+uaG16oc9ZNPS6qfBg=');

