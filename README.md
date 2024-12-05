# DomainSleuth

**DomainSleuth** es una herramienta diseñada para recopilar y analizar información sobre dominios, utilizando consultas WHOIS, registros DNS, y análisis de puertos para ayudar en tareas de ciberseguridad, reconocimiento y análisis de infraestructura digital.

## Características

- **Consulta WHOIS**: Obtiene información WHOIS detallada, como fechas de creación y expiración, información del propietario y datos de contacto del dominio.
- **Recuperación de registros DNS**: Identifica los servidores de nombres (NS) y de correo (MX) asociados al dominio.
- **Escaneo de puertos**: Realiza un escaneo de los 10 puertos más comunes para identificar servicios abiertos en el dominio.
- **Búsqueda de filtraciones**: Verifica posibles filtraciones de correo electrónico relacionadas con el dominio (requiere integración con IntelX API).

¡Aquí tienes el markdown en formato correcto para copiarlo directamente!

## Cómo descargar DomainSleuth

Puedes descargar **DomainSleuth** directamente desde nuestro repositorio de GitHub siguiendo estos pasos:

1. Abre una terminal en tu sistema operativo.
2. Clona el repositorio de GitHub con el siguiente comando:

   ```bash
   git clone https://github.com/SergioMahia/DomainSleuth.git
   ```

3. Accede a la carpeta del proyecto:

   ```bash
   cd DomainSleuth
   ```

4. Asegúrate de tener Python instalado y las dependencias requeridas configuradas. Instálalas ejecutando:

   ```bash
   pip install -r requirements.txt
   ```

5. ¡Listo! Ahora puedes ejecutar la herramienta directamente desde la terminal:

   ```bash
   python domainsleuth.py
   ```

## Ejemplo de ejecución

```
______                      _       _____ _            _   _     
|  _  \                    (_)     /  ___| |          | | | |    
| | | |___  _ __ ___   __ _ _ _ __ \ `--.| | ___ _   _| |_| |__  
| | | / _ \| '_ ` _ \ / _` | | '_ \ `--. \ |/ _ \ | | | __| '_ \ 
| |/ / (_) | | | | | | (_| | | | | /\__/ / |  __/ |_| | |_| | | |
|___/ \___/|_| |_| |_|\__,_|_|_| |_\____/|_|\___|\__,_|\__|_| |_|

Introduce el dominio (por ejemplo, 'ejemplo.com'): ejemplo.com

-------- Información de Registro del Dominio --------
[x] Dominio: ejemplo.com
[x] Registrado en: 1999-05-01
[x] Fecha de expiración: 2024-05-01
[x] Correos electrónicos (si existen): admin@ejemplo.com

-------- Información del Propietario --------
[x] Nombre propietario: John Doe
[x] País de registro: US
[x] Estado de registro: California
[x] Ciudad de registro: Los Angeles
[x] Código postal: 90001
[x] Dirección: 123 Example Street

Buscando filtraciones para el correo: admin@ejemplo.com
[ALERTA] Se encontraron posibles filtraciones para admin@ejemplo.com:

  - Nombre de la filtración: BreachDatabase2023
  - Fecha de la filtración: 2023-06-01
  - Contenido de la filtración: admin@ejemplo.com:password123

------- Enumerando puertos -------

[✔] Dominio operativo
[✔] Escaneando ejemplo.com...

Estado del host (ejemplo.com): up
Protocolo: tcp | Puerto: 80 | Estado: open
Protocolo: tcp | Puerto: 443 | Estado: open
Protocolo: tcp | Puerto: 21 | Estado: closed

------- Escaneando Servidores DNS -------

Servidores NS para ejemplo.com: ['ns1.ejemplo.com.', 'ns2.ejemplo.com.']
Servidores MX para ejemplo.com: [('mail.ejemplo.com.', 10), ('backupmail.ejemplo.com.', 20)]

```

---

### Desarrollado por Sergio Mahía
