# servidor/pki.py
import subprocess
import os
import sqlite3
import textwrap

from constantes.constantes import *


def ejecutar_comando_openssl(comando):
    """Ejecuta un comando OpenSSL y maneja la salida."""
    try:
        # Ejecuta el comando y espera a que finalice.
        resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
        print(f"OPENSSL EJECUTA: {' '.join(comando)}")
        
        # Muestra la salida si OpenSSL ha impreso algo
        if resultado.stdout:
            print(f"   Salida de OpenSSL:\n{resultado.stdout.strip()}")
            
        return True

    except subprocess.CalledProcessError as e:
        # Esto captura errores de OpenSSL (ej: archivo no encontrado)
        print(f"   ERROR: El comando OpenSSL ha fallado con código de salida {e.returncode}.")
        print(f"   Comando: {' '.join(e.cmd)}")
        print(f"   Mensaje de error (stderr):\n{e.stderr.strip()}")
        return False
    
    except FileNotFoundError:
        # Esto captura si el ejecutable 'openssl' no existe
        print("ERROR CRÍTICO: No se encontró el programa 'openssl'.")
        print("Por favor, asegúrate de que OpenSSL esté instalado y en tu PATH.")
        return False


def generar_clave_privada(ruta_privada, bits=4096):
    """
    Genera el par de claves RSA (privada y pública) en formato PEM.
    Acepta las rutas de los archivos como parámetros para ser reutilizable.
    """
    
    # Definimos los comandos de openssl
    comando_privada = ["openssl", "genrsa", "-out", ruta_privada, str(bits)]

    # Generamos la clave privada
    print(f"\n--- Generando clave privada RSA de {bits} bits en {ruta_privada} ---")

    if not ejecutar_comando_openssl(comando_privada):
        print("\nFALLO: No se puede continuar sin generar la clave privada.")
        return False

    # Si todo ha ido bien, mostramos por pantalla un mensaje de éxito
    print(f"Clave Privada generada con éxito\n")
    return True


def generar_certificado_autofirmado(ruta_priv, ruta_cert, ruta_cnf):
    print("--- Generando certificado autofirmado ---")
    comando_raiz = [
        "openssl", "req", "-x509", "-new", "-nodes", 
        "-key", ruta_priv, 
        "-sha256", "-days", "3650",
        "-out", ruta_cert, 
        "-config", ruta_cnf
    ]
    
    if not ejecutar_comando_openssl(comando_raiz):
        Exception("Fallo al generar el certificado autofirmado")
    print("Certificado autofirmado generado")


def generar_solicitud_certificado(ruta_priv, ruta_sol, ruta_cnf):
    """Recibe las direcciones de los ficheros para generar una solicitud de firma CSR"""
    
    print("--- Generando la Solicitud de Firma ---")

    comando_solicitar = [
        "openssl", "req", "-new", 
        "-key", ruta_priv, 
        "-out", ruta_sol, 
        "-config", ruta_cnf
    ]
    if not ejecutar_comando_openssl(comando_solicitar):
        Exception("La generación de la solicitud falló")
    
    print("Solicitud de firma generada correctamente\n")


def firmar_solicitud(ruta_solicitud, ruta_cnf_solicitante, ruta_cert_solicitante, ruta_cert_firmando, ruta_priv_firmando, ext):
    """Recibe las rutas de los ficheros necesarios para firmar y genera una firma en la dirección especificada"""

    print("--- Esperando respuesta a la Solicitud de Firma ---")

    comando_firma = [
        "openssl", "x509", "-req", 
        "-in", ruta_solicitud, 
        "-CA", ruta_cert_firmando, # Certificado de la Intermedia (quien firma)
        "-CAkey", ruta_priv_firmando, # Clave privada de la Intermedia
        "-extfile", ruta_cnf_solicitante, 
        "-extensions", ext, # Sección de extensiones del usuario
        "-out", ruta_cert_solicitante, # Certificado de salida del usuario
        "-sha256", 
        "-days", "365" # Válido por 1 año
    ]

    if not ejecutar_comando_openssl(comando_firma):
        Exception("La firma de la solicitud falló")
    
    print("Solicitud firmada con éxito\n")
    print("Certificado generado correctamente")


def generar_configuracion_raiz(ruta_cnf):
    """Genera el archivo .cnf para la CA Raíz (autofirmado, CA:true)."""

    print(f"--- Generando el Archivo de Configuración de la ACR ---")

    contenido = textwrap.dedent(f"""[ req ]
    prompt = no
    default_md = sha256
    distinguished_name = datos_identificacion
    x509_extensions = caracteristicas_acr

    [ datos_identificacion ]
    C = ES
    O = Certificadoras Españolas
    OU = Certificadora Raíz
    CN = Raíz de Confianza

    [ caracteristicas_acr ]
    basicConstraints = critical, CA:true
    keyUsage = critical, cRLSign, keyCertSign
    """)

    with open(ruta_cnf, 'w') as f:
        f.write(contenido)

    print(f"Archivo de configuración '{ruta_cnf}' generado correctamente.\n")
    

def generar_configuracion_intermedia(ruta_cnf):
    """Genera los archivos .cnf, .csr y .crt de la certificadora intermedia"""

    print(f"--- Generando el Archivo de Configuración ---")
    
    contenido = textwrap.dedent(f"""[ req ]
    prompt = no
    default_md = sha256
    distinguished_name = datos_identificacion
    req_extensions = caracteristicas_aci

    [ datos_identificacion ]
    C = ES                          # Código de País
    O = Certificadoras Españolas    # Organización
    OU = Certificadora Intermedia   # Unidad Organizacional (cambiado)
    CN = Intermedia de Firma        # Nombre Común (cambiado)

    [ caracteristicas_aci ]
    basicConstraints = critical, CA:true
    keyUsage = critical, cRLSign, keyCertSign""")
    
    with open(ruta_cnf, 'w') as f: 
        f.write(contenido)

    print(f"Archivo de configuración '{ruta_cnf}' generado correctamente.\n")


def generar_configuracion_servidor(ruta_cnf):
    """Genera el archivo .cnf para la CSR del servidor"""

    print(f"--- Generando el Archivo de Configuración del Servidor ---")

    dominio_servidor = "securnote.es"
    email_admin = "admin@miservidor.com"
    organizacion = "SecurNote"

    contenido = textwrap.dedent(f"""[ req ]
    prompt = no
    default_md = sha256
    distinguished_name = datos_identificacion
    req_extensions = caracteristicas_servidor

    [ datos_identificacion ]
    C = ES
    O = {organizacion}
    OU = IT
    # CN DEBE ser el FQDN del servidor (ej. www.miservidor.com)
    CN = {dominio_servidor}
    emailAddress = {email_admin}

    [ caracteristicas_servidor ]
    # 1. basicConstraints: CA:false para un certificado de entidad final
    basicConstraints = CA:false
    extendedKeyUsage = serverAuth
    subjectAltName = DNS:{dominio_servidor}
    keyUsage = digitalSignature, keyEncipherment
    """)
    
    with open(ruta_cnf, 'w') as f: 
        f.write(contenido)

    print(f"Archivo de configuración '{ruta_cnf}' generado correctamente.\n")


def generar_configuracion_usuario(nombre_usuario, email, ruta_cnf):
    """Genera y firma un certificado de entidad final (usuario) con la CA Intermedia."""
 
    print(f"\n==============================================")
    print(f"  INICIANDO CREACIÓN DE CERTIFICADO PARA {nombre_usuario.upper()}")
    print("==============================================")

    print(f"--- Generando el Archivo de Configuración de {nombre_usuario} ---")

    contenido = textwrap.dedent(f"""[ req ]
    prompt = no
    default_md = sha256
    distinguished_name = datos_identificacion
    req_extensions = caracteristicas_usuario

    [ datos_identificacion ]
    C = ES
    O = Aplicación de Notas
    OU = Usuario
    CN = {nombre_usuario}
    emailAddress = {email}

    [ caracteristicas_usuario ]
    # Debe ser CA:false para un certificado de entidad final
    basicConstraints = CA:false
    # Uso de clave extendido para autenticación de cliente (vital para TLS mutuo)
    extendedKeyUsage = clientAuth
    # Permite al navegador/cliente identificar el certificado por el nombre de usuario/email
    subjectAltName = DNS:{nombre_usuario}, email:{email}
    """)
    
    with open(ruta_cnf, 'w') as f: 
        f.write(contenido)

    print(f"Archivo de configuración '{ruta_cnf}' generado correctamente.\n")


def crear_ac_raiz(bits=4096):
    """
    Genera y firma el certificado de la Autoridad de Certificación Raíz.
    Este certificado es autofirmado.
    """
    print("\n==============================================")
    print("      INICIANDO CREACIÓN DE CA RAÍZ")
    print("==============================================")

    if not generar_clave_privada(CLAVE_PRIVADA_R, bits):
        return
    
    # Generamos el archivo de configuración para openssl
    generar_configuracion_raiz(CONFIGURACION_R)

    # Generamos el certificado haciendo uso de la clave privada y el archivo de configuracion
    generar_certificado_autofirmado(CLAVE_PRIVADA_R, CERTIFICADO_R, CONFIGURACION_R)


def crear_ac_intermedia(bits=4096):
    """
    Genera la Autoridad de Certificación Intermedia (ACI).
    Su certificado es firmado por la CA Raíz.
    """
    print("\n==============================================")
    print("   INICIANDO CREACIÓN DE CA INTERMEDIA")
    print("==============================================")

    if not generar_clave_privada(CLAVE_PRIVADA_I, bits):
        return

    # Generamos el archivo de configuracion para openssl   
    generar_configuracion_intermedia(CONFIGURACION_I)

    # Creamos el archivo de solicitud CSR
    generar_solicitud_certificado(CLAVE_PRIVADA_I, CSR_I, CONFIGURACION_I)

    # El firmante retorna el certificado firmado
    firmar_solicitud(CSR_I, CONFIGURACION_I, CERTIFICADO_I, CERTIFICADO_R, CLAVE_PRIVADA_R, "caracteristicas_aci")


def crear_certificado_servidor():
    """Genera y firma un certificado de entidad final (usuario) con la CA Intermedia."""
    print(f"\n==============================================")
    print(f"  INICIANDO CREACIÓN DE CERTIFICADO PARA EL SERVIDOR")
    print("==============================================")
    
    generar_clave_privada(CLAVE_PRIVADA_S)

    # Generamos el archivo de configuracion para openssl 
    generar_configuracion_servidor(CONFIGURACION_S)

    # Generamos la solicitud para la Autoridad de Certificación
    generar_solicitud_certificado(CLAVE_PRIVADA_S, CSR_S, CONFIGURACION_S)
    
    # Que luego firma la autoridad
    firmar_solicitud(CSR_S, CONFIGURACION_S, CERTIFICADO_S, CERTIFICADO_I, CLAVE_PRIVADA_I, "caracteristicas_servidor")


def crear_certificado_usuario(nombre, email, ruta_carpeta_usuario):
    """Genera y firma un certificado de entidad final (usuario) con la CA Intermedia."""
    
    ruta_cnf = os.path.join(ruta_carpeta_usuario, CONFIGURACION_C)
    ruta_priv = os.path.join(ruta_carpeta_usuario, CLAVE_PRIVADA_C)
    ruta_sol = os.path.join(ruta_carpeta_usuario, CSR_C)
    ruta_cert = os.path.join(ruta_carpeta_usuario, CERTIFICADO_C)
    
    generar_configuracion_usuario(nombre, email, ruta_cnf)

    # Hacemos la solicitud a la PKI
    generar_solicitud_certificado(ruta_priv, ruta_sol, ruta_cnf)

    # Firma de la solicitud
    firmar_solicitud(ruta_sol, ruta_cnf, ruta_cert, CERTIFICADO_I, CLAVE_PRIVADA_I, "caracteristicas_usuario")

    return ruta_cert


def crear_cadena_confianza():
    """
    Crea el archivo 'chain.pem' concatenando el certificado intermedio y el certificado raíz.
    Este archivo se usa para verificar la cadena completa de confianza.
    """

    print(f"\n==============================================")
    print(f"  Creando la cadena de confianza en {CHAIN_PATH}")
    print("==============================================")
    
    try:
        # La cadena debe ir de Intermedia a Raíz
        with open(CERTIFICADO_I, 'r') as f_i, open(CERTIFICADO_R, 'r') as f_r, open(CHAIN_PATH, 'w') as f_chain:
            f_chain.write(f_i.read())
            f_chain.write(f_r.read())
        print(f"Cadena de Confianza creada exitosamente.")
        return CHAIN_PATH
    except FileNotFoundError as e:
        print(f"   ERROR: No se pudieron leer los archivos para crear la cadena: {e}")
        return None
    
if __name__ == "__main__":
    pass