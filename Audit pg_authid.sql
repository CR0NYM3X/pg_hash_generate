WITH weak_passwords_dictionary AS (
    -- 1. Diccionario Estático (Secuencias, Corporativas, Teclado, Diccionario)
    SELECT unnest(ARRAY[
        -- Secuencias y Repeticiones
        '123','1234','12345','123456','1234567','12345678','123456789','1234567890','0000','00000','1111', '111111' ,'123123','654321','55555',
        -- Corporativas y Defecto
        'admin','administrator','password','p@ssword','root','support','guest','user','login','welcome',
        'postgres','sysadmin','password123','superbowl 123','temporal','cambiar01','P4ssw0rd','4dm1n',
        -- Teclado
        'qwerty','asdfgh','zxcvbnm','qazwsx','poiuyt','1q2w3e','qwertyuiop','asdfghjkl','asdasd',
        -- Diccionario Común
        'monkey','dragon','football','soccer','starwars','superman','batman','charlie','shadow','login', 'secret', 'quertyuiop', 'welcome', 'abc123',
        -- Fechas
        '2022','2023','2024','2025','2026'
    ]) AS test_password
    
    UNION
    
    -- 2. Diccionario Dinámico (Serie superbowl 1990 - superbowl 2026)
    SELECT 'superbowl ' || year_val FROM generate_series(1990, 2026) AS year_val
    
    UNION
    
    -- 3. Diccionario Dinámico (Serie superbowl 1990 - superbowl 2026)
    SELECT 'superbowl ' || year_val FROM generate_series(1990, 2026) AS year_val
)
SELECT 
    a.rolname AS username,
    CASE 
        WHEN a.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256'
        WHEN a.rolpassword LIKE 'md5%' THEN 'MD5'
        ELSE 'Unknown/Other'
    END AS algorithm_type,
    d.test_password AS detected_password,
    CASE 
        WHEN a.rolsuper THEN 'CRITICAL'
        ELSE 'HIGH'
    END AS risk_level
FROM pg_authid a
CROSS JOIN weak_passwords_dictionary d
WHERE a.rolpassword IS NOT NULL
  AND (
    -- Caso 1: Si es SCRAM, usa pg_scram_sha256_verify
    (a.rolpassword LIKE 'SCRAM-SHA-256$%' AND public.pg_scram_sha256_verify(d.test_password, a.rolpassword))
    OR
    --Caso 2: Si es MD5, usa pg_md5_verify (requiere username para el salt)
    (a.rolpassword LIKE 'md5%' AND public.pg_md5_verify(a.rolname, d.test_password, a.rolpassword))
  )
ORDER BY a.rolsuper DESC, a.rolname ASC;





