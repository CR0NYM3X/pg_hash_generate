
# 🔐 pg_hash_generate Toolkit

Una suite de funciones robustas en PL/pgSQL para generar y validar hashes de contraseñas bajo el estándar SCRAM-SHA-256 (RFC 7677) y MD5. Ideal para sistemas que requieren gestionar autenticación personalizada o migraciones seguras de usuarios o realizar auditorias internas utilizando diccionarios personalizados.

---

##  ¿Qué es SCRAM-SHA-256?

**Salted Challenge Response Authentication Mechanism (SCRAM)** es el estándar de oro actual para la autenticación en PostgreSQL. A diferencia de MD5, SCRAM ofrece una resistencia superior contra ataques de fuerza bruta y de diccionario,  un factor de costo (iteraciones) y una verificación de mutua confianza entre el cliente y el servidor.

### 🛡️ 1. SCRAM-SHA-256 (Recomendado)

El hash generado por este proyecto es compatible con el formato interno de PostgreSQL:

#### 🏗️ Anatomía del Hash SCRAM
`SCRAM-SHA-256$ <Iteraciones> : <Salt> $ <StoredKey> : <ServerKey>`


| Componente | Función |
| --- | --- |
| **Iteraciones** | El factor de costo (PBKDF2). A mayor número, más lento el ataque de fuerza bruta. |
| **Salt** | Datos aleatorios únicos por usuario que evitan el uso de "Rainbow Tables". |
| **StoredKey** | Hash derivado de la clave del cliente; es lo que se compara para validar el acceso. |
| **ServerKey** | Permite al cliente verificar que el servidor realmente conoce la clave (Autenticación mutua). |


## 📜 2. MD5 (Legacy)

Es el método de autenticación clásico de PostgreSQL (versiones 13 y anteriores). Aunque es más rápido, es menos seguro que SCRAM frente a ataques modernos debido a la falta de un factor de costo ajustable.

#### 🏗️ Anatomía del Hash MD5

PostgreSQL utiliza una implementación específica que combina la contraseña con el nombre de usuario como una "sal" (salt) básica:

`md5 || md5( password || username )`

| Componente | Función |
| --- | --- |
| **Prefijo `md5`** | Identificador de cadena que indica a PostgreSQL el tipo de algoritmo. |
| **Username** | Se utiliza como sal dinámica; si el usuario cambia de nombre, el hash deja de ser válido. |
| **password** | es la palabra que se utilizara como contraseña. |

--- 

## 📋 Requisitos de Instalación

1. **Activar Criptografía**:
```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

```


2. **Seguridad de Acceso**:
```sql
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fn_util_verify_scram_sha256 TO rol_aplicacion;

```


---

## 🚀 Ventajas del Proyecto

1. **Transparencia Total**: Retorno en formato `TABLE` para un desglose detallado de cada componente criptográfico.
2. **Validación Estricta**: Nuestra función de verificación comprueba tanto la `StoredKey` como la `ServerKey`, garantizando que el hash no haya sido corrompido ni alterado (protección contra manipulación de datos).
3. **Portabilidad HTML**: Incluimos una interfaz web para pruebas rápidas sin tocar la base de datos.
4. **Independencia del Motor**: Permite validar contraseñas SCRAM desde aplicaciones externas o capas de lógica de negocio sin exponer las tablas de sistema de Postgres.
5. **Cero Dependencias Externas**: Solo requiere la extensión nativa `pgcrypto`.

---

## 🖥️ Herramienta Interactiva (HTML)

Para facilitar las pruebas y la depuración fuera del entorno SQL, este proyecto incluye una utilidad visual:

👉 **[Calculadora SCRAM-SHA-256 Interactiva](https://github.com/CR0NYM3X/pg_scram_sha256_generate/blob/main/pg_scram_sha256_generate.html)**

Esta herramienta permite generar los componentes del hash directamente en el navegador, ideal para validar que los cálculos en el backend coincidan perfectamente con los estándares del cliente.

---

## 🛠️ Casos de Uso

* **Sistemas de Auth Propios**: Crear tu propia tabla de usuarios con el mismo nivel de seguridad que el motor de Postgres.
* **Auditoría Estricta**: Verificación de integridad de hashes almacenados para detectar alteraciones maliciosas.


---

## 💻 Ejemplos de Código

### 1. Generación Desglosada (Registro)

```sql
-- iteraciones por defecto : 4096
postgres@postgres# SELECT * FROM public.pg_scram_sha256_generate('password123', 4096);
+-[ RECORD 1 ]+---------------------------------------------------------------------------------------------------------------------------------------+
| hash        | SCRAM-SHA-256$4096:c8F0iUD3+l/hg4zzohVnXQ==$OLogK2jd8+J3tSHe6un2ls3uHkGW9gQ37jO6GJ4ZPDk=:7iJgiVEa7hbe6nSGkdYMkdqhCEYsK0GS/hAiQzs4KUM= |
| algoritmo   | SCRAM-SHA-256                                                                                                                         |
| iteraciones | 4096                                                                                                                                  |
| salt        | c8F0iUD3+l/hg4zzohVnXQ==                                                                                                              |
| stored_key  | OLogK2jd8+J3tSHe6un2ls3uHkGW9gQ37jO6GJ4ZPDk=                                                                                          |
| server_key  | 7iJgiVEa7hbe6nSGkdYMkdqhCEYsK0GS/hAiQzs4KUM=                                                                                          |
+-------------+---------------------------------------------------------------------------------------------------------------------------------------+

Time: 27.906 ms


postgres@postgres# SELECT * FROM public.pg_scram_sha256_generate('password123', 10000);
+-[ RECORD 1 ]+----------------------------------------------------------------------------------------------------------------------------------------+
| hash        | SCRAM-SHA-256$10000:h69vMnHhz6h18mPLRMNPAA==$cT4x4CTkpyf+K9nUobqQl/igZsBa4PyPysjzTEfBO/I=:a26eDR/u6wtzG2pER6X2glivwQYjBvqo0BABxU2koXE= |
| algoritmo   | SCRAM-SHA-256                                                                                                                          |
| iteraciones | 10000                                                                                                                                  |
| salt        | h69vMnHhz6h18mPLRMNPAA==                                                                                                               |
| stored_key  | cT4x4CTkpyf+K9nUobqQl/igZsBa4PyPysjzTEfBO/I=                                                                                           |
| server_key  | a26eDR/u6wtzG2pER6X2glivwQYjBvqo0BABxU2koXE=                                                                                           |
+-------------+----------------------------------------------------------------------------------------------------------------------------------------+

Time: 65.754 ms

postgres@postgres# SELECT * from public.pg_md5_generate( 'user_test', 'password123') AS hash_md5;  
+-------------------------------------+
|              hash_md5               |
+-------------------------------------+
| md5a55cc73725a729b561ecfc4984d922a9 |
+-------------------------------------+
(1 row)



```

### 2. Verificación (Login)

```sql
-- Retornará 't' solo si el hash es íntegro y la clave es correcta
select * from public.pg_scram_sha256_verify(
  'password123',
  'SCRAM-SHA-256$10000:BfjFRQ5cJh8ORscTYOuwuQ==$5a5hkxA6mouSmmCl4m0yd/klStxHVBLp8dLTPbRwLj4=:VuswwU3Muvs2p1q0Oxu7P7rhk+uaG16oc9ZNPS6qfBg='); -- validacion correcta 

+------------------------+
| pg_scram_sha256_verify |
+------------------------+
| t                      |
+------------------------+
(1 row)


postgres@postgres# SELECT * FROM public.pg_md5_verify('user_test','password123', 'md5a55cc73725a729b561ecfc4984d922a9');
+---------------+
| pg_md5_verify |
+---------------+
| t             |
+---------------+
(1 row)


SELECT usename,public.pg_scram_sha256_verify('123123' , passwd )  
FROM pg_shadow 
where usename in('user_test', 'test' , 'postgres') 
order by 2 desc;

+-----------+------------------------+
|  usename  | pg_scram_sha256_verify |
+-----------+------------------------+
| user_test | t                      |
| postgres  | f                      |
| test      | f                      |
+-----------+------------------------+
(3 rows)
```



## Auditorias de Seguridad 

```SQL

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
    SELECT 'America ' || year_val FROM generate_series(1990, 2026) AS year_val
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


+-----------+----------------+-------------------+------------+
| username  | algorithm_type | detected_password | risk_level |
+-----------+----------------+-------------------+------------+
| postgres  | SCRAM-SHA-256  | P4ssw0rd          | CRITICAL   |
| user_test | MD5            | secret            | HIGH       |
+-----------+----------------+-------------------+------------+
(2 rows)

Time: 13065.403 ms (00:13.065)
```

 

## ✅ Características Principales

- ✅ **Implementación correcta de PBKDF2** con HMAC-SHA256
- ✅ **Salt aleatorio de 16 bytes** (128 bits) en cada generación
- ✅ **4096 iteraciones por defecto** (configurable)
- ✅ **Formato exacto de PostgreSQL**: `SCRAM-SHA-256$iter:salt$stored:server`
- ✅ **XOR correcto** de iteraciones en PBKDF2
- ✅ **StoredKey = H(ClientKey)** según RFC 7677
- ✅ **Base64 limpio** sin saltos de línea
- ✅ **Validaciones de entrada** (NULL, vacío, rangos)
- ✅ **Compatible con todas las versiones** de PostgreSQL que soportan pgcrypto



### Referencias

- [RFC 7677](https://datatracker.ietf.org/doc/html/rfc7677) - SCRAM-SHA-256
- [RFC 5802](https://datatracker.ietf.org/doc/html/rfc5802) - SCRAM
- [RFC 2898](https://datatracker.ietf.org/doc/html/rfc2898) - PBKDF2
- [PostgreSQL Password Authentication](https://www.postgresql.org/docs/current/auth-password.html)




---

**Mantenido por:** `CR0NYM3X` | **Versión:** 1.0.0 (2026)
 
