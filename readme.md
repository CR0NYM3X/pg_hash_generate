
# 🔐 PostgreSQL SCRAM-SHA-256 Toolkit

Una suite de funciones robustas en PL/pgSQL para generar y validar hashes de contraseñas bajo el estándar SCRAM-SHA-256 (RFC 7677). Ideal para sistemas que requieren gestionar autenticación personalizada o migraciones seguras de usuarios.

---

## 🧠 ¿Qué es SCRAM-SHA-256?

**Salted Challenge Response Authentication Mechanism (SCRAM)** es el estándar de oro actual para la autenticación en PostgreSQL. A diferencia de MD5, SCRAM ofrece una resistencia superior contra ataques de fuerza bruta y de diccionario,  un factor de costo (iteraciones) y una verificación de mutua confianza entre el cliente y el servidor.

### 🏗️ Anatomía del Hash

El hash generado por este proyecto es compatible con el formato interno de PostgreSQL:

`SCRAM-SHA-256$ <Iteraciones> : <Salt> $ <StoredKey> : <ServerKey>`

| Componente | Función |
| --- | --- |
| **Iteraciones** | El factor de costo (PBKDF2). A mayor número, más lento el ataque de fuerza bruta. |
| **Salt** | Datos aleatorios únicos por usuario que evitan el uso de "Rainbow Tables". |
| **StoredKey** | Hash derivado de la clave del cliente; es lo que se compara para validar el acceso. |
| **ServerKey** | Permite al cliente verificar que el servidor realmente conoce la clave (Autenticación mutua). |


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
* **Gestión Usuarios**: Scripts de automatización que crean usuarios de BD solo si no existen, aplicando hashes SCRAM.
* **Auditoría Estricta**: Verificación de integridad de hashes almacenados para detectar alteraciones maliciosas.


---

## 💻 Ejemplos de Código

### 1. Generación Desglosada (Registro)

```sql
SELECT * FROM public.fn_util_generate_scram_sha256('password123', 4096);
SELECT * FROM public.fn_util_generate_scram_sha256('password123', 10000);


```

### 2. Verificación Estricta (Login)

```sql
-- Retornará 't' solo si el hash es íntegro y la clave es correcta
select * from public.pg_verify_scram_sha256(
  'password123',
  'SCRAM-SHA-256$10000:BfjFRQ5cJh8ORscTYOuwuQ==$5a5hkxA6mouSmmCl4m0yd/klStxHVBLp8dLTPbRwLj4=:VuswwU3Muvs2p1q0Oxu7P7rhk+uaG16oc9ZNPS6qfBg='); -- validacion correcta 


SELECT usename,public.pg_verify_scram_sha256('123123' , passwd )  
FROM pg_shadow 
where usename in('user_test', 'test' , 'postgres') 
order by 2 desc;

+-----------+------------------------+
|  usename  | pg_verify_scram_sha256 |
+-----------+------------------------+
| user_test | t                      |
| postgres  | f                      |
| test      | f                      |
+-----------+------------------------+
(3 rows)
```



 

---

**Mantenido por:** `CR0NYM3X` | **Versión:** 1.0.0 (2026)
 
