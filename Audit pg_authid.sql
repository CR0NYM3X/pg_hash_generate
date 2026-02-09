------------------------ OPCION #1 ------------------------


DO $auditoria_seguridad$
DECLARE
    -- Listado de las 20 contraseñas más débiles
    v_diccionario text[] := ARRAY[
        '123456', 'password', '123456789', '12345', '12345678', 
        'qwerty', '111111', '123123', 'admin', 'p@ssword', 
        'welcome', 'abc123', 'login', 'secret', 'asdfgh', 
        '1234567', 'monkey', 'dragon', 'football', 'quertyuiop'
    ];
    
    v_usuario     record;
    v_pass_debil  text;
    v_es_valida   boolean;
    v_hallazgos   integer := 0;
BEGIN
    RAISE NOTICE '========== INICIANDO AUDITORÍA DE CONTRASEÑAS ==========';
    RAISE NOTICE 'Revisando usuarios contra el Top 20 de contraseñas débiles...';
    RAISE NOTICE '--------------------------------------------------------';

    -- 1. Iterar sobre todos los roles que tienen una contraseña definida
    FOR v_usuario IN 
        SELECT rolname, rolpassword 
        FROM pg_authid 
        WHERE rolpassword IS NOT NULL 
          AND rolpassword LIKE 'SCRAM-SHA-256$%'
    LOOP
        -- 2. Probar cada contraseña del diccionario contra el hash del usuario
        FOREACH v_pass_debil IN ARRAY v_diccionario
        LOOP
            -- Usamos nuestra función de validación estricta
            v_es_valida := public.pg_scram_sha256_verify(v_pass_debil, v_usuario.rolpassword);
            
            IF v_es_valida THEN
                RAISE WARNING 'RIESGO DETECTADO: El usuario "%" utiliza la contraseña débil: "%"', 
                              v_usuario.rolname, v_pass_debil;
                v_hallazgos := v_hallazgos + 1;
            END IF;
        END LOOP;
    END LOOP;

    -- 3. Reporte Final
    RAISE NOTICE '--------------------------------------------------------';
    IF v_hallazgos = 0 THEN
        RAISE NOTICE 'AUDITORÍA FINALIZADA: No se encontraron vulnerabilidades.';
    ELSE
        RAISE WARNING 'AUDITORÍA FINALIZADA: Se encontraron % vulnerabilidades.', v_hallazgos;
    END IF;
    RAISE NOTICE '========================================================';

EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'ERROR DURANTE AUDITORÍA: %', SQLERRM;
END $auditoria_seguridad$;


------------------------ OPCION #2 ------------------------



SELECT 
    a.rolname AS vulnerable_user,
    d.password_test AS detected_password,
    'CRITICAL' AS risk_level
FROM pg_authid a
CROSS JOIN (
    -- Generate an on-the-fly virtual table with the top 20 weak passwords
    SELECT unnest(ARRAY[
        '123456', 'password', '123456789', '12345', '12345678', 
        'qwerty', '111111', '123123', 'admin', 'p@ssword', 
        'welcome', 'abc123', 'login', 'secret', 'asdfgh', 
        '1234567', 'monkey', 'dragon', 'football', 'quertyuiop'
    ]) AS password_test
) d
WHERE a.rolpassword IS NOT NULL 
  AND a.rolpassword LIKE 'SCRAM-SHA-256$%'
  -- Invoke your custom validation function
  AND public.pg_scram_sha256_verify(d.password_test, a.rolpassword) = TRUE;





