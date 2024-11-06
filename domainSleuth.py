import re
import nmap
import whois
import dns.resolver
from ping3 import ping
from intelxapi import intelx


def obtener_whois(dominio):
    try:
        # Consulta la información WHOIS del dominio
        info_whois = whois.whois(dominio, intelx_handler)
        
        # Muestra la información de registro relevante
        print("\n-------- Información de Registro del Dominio --------")
        print(f"[x] Dominio: {dominio}")
        print(f"[x] Registrado en: {info_whois.creation_date}")
        print(f"[x] Fecha de expiración: {info_whois.expiration_date}")
        print(f"[x] Correos electrónicos (si existen): {info_whois.emails or 'No disponible'}")

        # Muestra la información del propietario
        print("\n-------- Información del Propietario --------")
        print(f"[x] Nombre propietario: {info_whois.name or 'No disponible'}")
        print(f"[x] País de registro: {info_whois.country or 'No disponible'}")
        print(f"[x] Estado de registro: {info_whois.state or 'No disponible'}")
        print(f"[x] Ciudad de registro: {info_whois.city or 'No disponible'}")
        print(f"[x] Código postal: {info_whois.registrant_postal_code or 'No disponible'}")
        print(f"[x] Dirección: {info_whois.address or 'No disponible'}")

        # Si existen correos electrónicos, busca posibles filtraciones para cada uno
        if info_whois.emails:
            for email in info_whois.emails:
                print(f"\nBuscando filtraciones para el correo: {email}")
                buscar_filtracion(intelx_handler, email)
        
        return info_whois
    except Exception as e:
        print(f"Error al obtener WHOIS para {dominio}: {e}")

def buscar_filtracion(handler, email):
    """
    Busca posibles filtraciones de un correo electrónico en Intelligence X y muestra contenido relevante.
    """

    b = [
        'leaks.public.wikileaks',
        'leaks.public.general',
        'dumpster',
        'dumpster.web.1',
        'dumpster.web.ssn',
        'documents.public.scihub'
    ]

    try:
        
        # Realizamos una búsqueda rápida en Intelligence X para el correo
        resultados = handler.search(email, maxresults=10, buckets=b)
        
        # Comprobamos si hay resultados
        if resultados['records']:
            print(f"[ALERTA] Se encontraron posibles filtraciones para {email}:\n")
            for resultado in resultados['records']:
                print(f"  - Nombre de la filtración: {resultado['name']}")
                print(f"  - Fecha de la filtración: {resultado['date']}")

                # Obtener una vista del contenido de la filtración
                contenido = obtener_vista_contenido(handler, resultado, email)
                if contenido:
                    print(f"  - Contenido de la filtración: {contenido}")
                
                print("\n")
        else:
            print(f"No se encontraron filtraciones para {email}.")

    except Exception as e:
        print(f"Error al buscar filtración para {email}: {e}")

def obtener_vista_contenido(handler, resultado, email):
    try:
        # Usamos FILE_VIEW para obtener el contenido como texto
        contenido = handler.FILE_VIEW(
            resultado['type'],
            resultado['media'],
            resultado['storageid'],
            resultado['bucket']
        )

        # Buscar y devolver solo la línea que contiene el correo
        for line in contenido.splitlines():
            if re.search(rf"\b{re.escape(email)}\b", line):  # Búsqueda exacta del correo
                return line
        return "Correo no encontrado en la vista previa del contenido."
    except Exception as e:
        print(f"Error al obtener vista del contenido: {e}")
        return None

def comprobar_conexion(dominio):
    try:
        resultado = ping(dominio, timeout=60)
        return resultado is not None
    except PermissionError:
        print(f"No se pudo comprobar la conexión a {dominio}. Se requieren privilegios de root.")
    except Exception as e:
        print(f"Ocurrió un error al intentar conectar con {dominio}: {e}")
    
    return False

def enumerar_top_10_puertos(dominio):
    # Verificar conexión
    if comprobar_conexion(dominio):
        print("------- Enumerando puertos -------\n")
        print("[\u2713] Dominio operativo")
        
        # Crear instancia del escáner
        nmap_scanner = nmap.PortScanner()
        print(f"[\u2713] Escaneando {dominio}...\n")

        # Escanear los 10 puertos principales
        nmap_scanner.scan(hosts=dominio, arguments='--top-ports 10')

        # Mostrar resultados del escaneo
        for host in nmap_scanner.all_hosts():
            print(f"Estado del host ({host}): {nmap_scanner[host].state()}")
            for protocolo in nmap_scanner[host].all_protocols():
                puertos = nmap_scanner[host][protocolo].keys()
                for puerto in puertos:
                    estado = nmap_scanner[host][protocolo][puerto]['state']
                    print(f"Protocolo: {protocolo} | Puerto: {puerto} | Estado: {estado}")
    else:
        print("[X] Dominio inalcanzable")

def obtener_registros_dns(dominio):
    print("\n------- Escaneando Servidores DNS -------\n")

    try:
        respuesta = dns.resolver.resolve(dominio, 'NS')
        ns_servers = [str(rdata) for rdata in respuesta]
        print(f"Servidores NS para {dominio}: {ns_servers}")
    except Exception as e:
        return f"Error al obtener registros NS: {e}"
    
    try:
        respuesta = dns.resolver.resolve(dominio, 'MX')
        mx_servers = [(str(rdata.exchange), rdata.preference) for rdata in respuesta]
        print(f"Servidores MX para {dominio}: {mx_servers}")
    except Exception as e:
        return f"Error al obtener registros MX: {e}"


if __name__ == "__main__":
    # Inicializa el handler de Intelligence X con la clave API
    API_KEY = '00000000-0000-0000-0000-000000000000'
    intelx_handler = intelx(API_KEY)

    # Solicita al usuario que ingrese el dominio
    dominio = input("Introduce el dominio (por ejemplo, 'ejemplo.com'): ")
    
    # Llama a las funciones necesarias
    obtener_whois(dominio, intelx_handler)
    enumerar_top_10_puertos(dominio)

    obtener_registros_dns(dominio)
