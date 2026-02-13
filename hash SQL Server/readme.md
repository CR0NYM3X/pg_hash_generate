 
## Consideraciones Técnicas  

* **Dependencia Crítica:** El uso de la extensión `pgcrypto` es obligatorio, ya que PostgreSQL nativo no incluye `digest()` ni `gen_random_bytes()` en su núcleo estándar.
* **El desafío del UTF-16LE:** PostgreSQL maneja strings usualmente en UTF-8. SQL Server utiliza `UTF-16 Little Endian` para sus tipos `NVARCHAR` y para el proceso de hashing de contraseñas. La función debe emular esto inyectando bytes nulos (`\x00`) para que el hash resultante sea idéntico.
* **Orden de Concatenación:** A diferencia de otros estándares, SQL Server concatena la **Contraseña + Salt** antes de aplicar el hash. Hacerlo al revés (`Salt + Pass`) resultará en una validación fallida.
* **Encabezados de Versión:**
* `0x0100`: Utiliza SHA-1 (Legacy/SQL Server 2000-2008 R2).
* `0x0200`: Utiliza SHA-512 (Moderno/SQL Server 2012+).



---

## Datos Interesantes (Fun Facts para el README)

1. **Seguridad por Oscuridad:** Las funciones `PWDENCRYPT` y `PWDCOMPARE` de Microsoft no están documentadas oficialmente y se consideran "internas", aunque se han usado por décadas en sistemas .NET.
2. **Longitud del Hash:** Un hash de SQL Server tipo `0x0200` siempre tendrá una longitud de **54 bytes** (2 bytes de encabezado + 4 bytes de sal + 48 bytes de hash SHA-512 truncado/específico) o hasta **128 bytes** dependiendo de la implementación del buffer.
3. **Compatibilidad Multi-lenguaje:** Con esta implementación en PL/pgSQL, una aplicación escrita en Python, Go o Node.js puede validar usuarios migrados de SQL Server sin necesidad de librerías externas de criptografía de Windows.

---
 

2. **Cargar funciones:** Ejecuta los archivos `.sql` en tu base de datos.
3. **Validar un usuario migrado:**
```sql

select * from pg_mssql_sha512_generate('Test123');

SELECT pg_mssql_sha512_verify(
    'Test123', 
    '0x02001CF0E6CD2181A220D7923EAF8F4648C71089BF4538E62DD71F1DF11FFFC098204404B0FF76D53EF31E04125ECD15112A2459965CBDD7FB4F92C6895C32194418C4921808'
);

```


 
