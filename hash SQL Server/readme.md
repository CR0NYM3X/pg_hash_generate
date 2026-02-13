 
## Consideraciones Técnicas  

* **Dependencia Crítica:** El uso de la extensión `pgcrypto` es obligatorio, ya que PostgreSQL nativo no incluye `digest()` ni `gen_random_bytes()` en su núcleo estándar.
* **El desafío del UTF-16LE:** PostgreSQL maneja strings usualmente en UTF-8. SQL Server utiliza `UTF-16 Little Endian` para sus tipos `NVARCHAR` y para el proceso de hashing de contraseñas. La función debe emular esto inyectando bytes nulos (`\x00`) para que el hash resultante sea idéntico.
* **Orden de Concatenación:** A diferencia de otros estándares, SQL Server concatena la **Contraseña + Salt** antes de aplicar el hash. Hacerlo al revés (`Salt + Pass`) resultará en una validación fallida.
* **Encabezados de Versión:**
* `0x0100`: Utiliza SHA-1 (Legacy/SQL Server 2000-2008 R2).
* `0x0200`: Utiliza SHA-512 (Moderno/SQL Server 2012+).



---

## Datos Interesantes 

1. **Seguridad por Oscuridad:** Las funciones `PWDENCRYPT` y `PWDCOMPARE` de Microsoft no están documentadas oficialmente y se consideran "internas", aunque se han usado por décadas en sistemas .NET.
2. **Longitud del Hash:** Un hash de SQL Server tipo `0x0200` siempre tendrá una longitud de **54 bytes** (2 bytes de encabezado + 4 bytes de sal + 48 bytes de hash SHA-512 truncado/específico) o hasta **128 bytes** dependiendo de la implementación del buffer.
3. **Compatibilidad Multi-lenguaje:** Con esta implementación en PL/pgSQL, una aplicación escrita en Python, Go o Node.js puede validar usuarios migrados de SQL Server sin necesidad de librerías externas de criptografía de Windows.

---



### 1. Los Encabezados Estándar

* **`0x0100` (Legacy):** Utilizado en SQL Server 2000, 2005 y 2008. Se basa en el algoritmo **SHA-1**. Aunque es antiguo, muchas bases de datos migradas todavía lo conservan.
* **`0x0200` (Moderno):** Introducido en SQL Server 2012 y utilizado en todas las versiones posteriores (2014, 2016, 2017, 2019, 2022). Utiliza **SHA-512**. Es el que validamos en tu imagen.


### 2. Versiones "Raras" o de Transición

Aunque no son comunes, existen estas variantes:

* **`0x00` / Sin encabezado:** En versiones prehistóricas de SQL Server (v6.5 o anteriores), el hashing era mucho más simple y no incluía un encabezado de versión tan claro. No suelen sobrevivir en migraciones modernas.
* **Azure SQL Edge:** En algunas implementaciones muy específicas de IoT o versiones ligeras, SQL Server puede comportarse de forma distinta, pero generalmente respeta el estándar `0x0200` para mantener la compatibilidad con ADO.NET.

 

## Consideraciones para tu Repositorio

Para que tu repositorio sea una referencia técnica de "grado senior", te sugiero incluir esta tabla comparativa en el `README.md`:

| Header | Algoritmo | Versión SQL Server | Seguridad |
| --- | --- | --- | --- |
| **`0x0100`** | SHA-1 | 2000 - 2008 R2 | **Baja** (Vulnerable a colisiones) |
| **`0x0200`** | SHA-512 | 2012 - 2022+ | **Alta** (Estándar actual) |




## Ejemplo de uso  
```sql

select * from pg_mssql_sha512_generate('Test123');

SELECT pg_mssql_sha512_verify(
    'Test123', 
    '0x02001CF0E6CD2181A220D7923EAF8F4648C71089BF4538E62DD71F1DF11FFFC098204404B0FF76D53EF31E04125ECD15112A2459965CBDD7FB4F92C6895C32194418C4921808'
);

```

# Links ref
```
 https://www.detfalskested.dk/2022/12/07/reimplementing-microsoft-sql-server-pwdencrypt-pwdcompare-in-python/
```

 
