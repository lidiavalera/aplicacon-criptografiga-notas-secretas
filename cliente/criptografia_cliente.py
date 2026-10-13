# cliente/criptografia_cliente.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from servidor.criptografia import verificar_hmac
from pathlib import Path
from servidor.pki import ejecutar_comando_openssl
from constantes.constantes import *


def generar_clave_cliente():
    """Genera una clave privada de 2048 bits"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


def descifrar_texto(clave, texto_cifrado_b64):
    """Descifra texto cifrado con AES-GCM."""
    aesgcm = AESGCM(clave) # Crear un objeto AES-GCM con la clave proporcionada.
    datos = base64.b64decode(texto_cifrado_b64) # Decodificar el texto cifrado que viene en base64 a bytes.
    nonce = datos[:12] # Los primeros 12 bytes son el nonce.
    ciphertext = datos[12:] # El resto es el texto cifrado.
    texto_descifrado = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8') # Desciframos el texto con AES-GCM. El tercer parámetro es para datos adicionales autenticados (AAD), que no usamos aquí, y el resultado lo decodificamos de bytes a string (UTF-8).
    print("Descifrado AES-GCM aplicado correctamente.")
    return texto_descifrado


def cifrar_clave_privada(clave_privada_serializada, contraseña):
    """
    Cifra bytes (datos_bytes) usando AES-GCM.
    Deriva la clave AES de 256 bits desde la contraseña del usuario usando PBKDF2.
    Devuelve un string base64 que contiene: salt + nonce + ciphertext
    """
    salt = os.urandom(16) # Generar salt aleatorio

    # Derivar la contraseña para usarla como clave para AES-GCM de 256 bits
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    clave_aes = kdf.derive(contraseña.encode())

    # Cifraramos la clave privada serializada con AES-GCM
    aesgcm = AESGCM(clave_aes)
    nonce = os.urandom(12)  # nonce de 12 bytes necesario para AES-GCM
    ciphertext = aesgcm.encrypt(nonce, clave_privada_serializada, None)

    # Devolver base64: salt + nonce + ciphertext
    return base64.b64encode(salt + nonce + ciphertext).decode('utf-8')


def descifrar_clave_privada(clave_privada_b64, contraseña):
    """
    Descifra un string base64 cifrado con AES-GCM usando clave derivada de contraseña.
    Devuelve los bytes originales.
    """
    datos = base64.b64decode(clave_privada_b64)

    # Extraer salt, nonce y ciphertext
    salt = datos[:16]
    nonce = datos[16:28]  # 12 bytes
    ciphertext = datos[28:]

    # Derivar clave AES de 256 bits desde la contraseña y el salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    clave_aes = kdf.derive(contraseña.encode())

    # Descifrar con AES-GCM
    aesgcm = AESGCM(clave_aes)
    datos_descifrados = aesgcm.decrypt(nonce, ciphertext, None)
    return datos_descifrados


def descifrar_RSA(clave_privada, clave_aes):
    """Descifra la clave_aes con la clave privada RSA usando OAEP+SHA256, recomendado y estándar para cifrado RSA según NIST"""
    descifrado = clave_privada.decrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return descifrado  # bytes


def serializar_clave_publica(clave_publica):
    """Convierte clave pública a formato PEM string para almacenar"""
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


def serializar_clave_privada(clave_privada):
    """
    Serializa la clave privada a bytes PEM sin cifrar. Solo convierte la clave privada en bytes PEM.
    """
    return clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def deserializar_clave_publica(clave_publica_str):
    """Recupera clave pública desde string PEM"""
    return serialization.load_pem_public_key(
        clave_publica_str.encode('utf-8'),
        backend=default_backend()
    )


def deserializar_clave_privada(clave_privada_bytes):
    """
    Recupera un objeto de clave privada desde bytes PEM descifrados.
    """
    return serialization.load_pem_private_key(
        clave_privada_bytes,
        password=None,
        backend=default_backend()
    )


def exportar_clave_publica_pem(clave_publica, ruta):
    """Guarda la clave pública RSA en formato PEM para OpenSSL (para el certificado de usuario)"""
    datos = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(ruta, "wb") as f:
        f.write(datos)


def exportar_clave_privada_pem(clave_privada_obj, ruta):
    """Guarda la clave privada RSA en formato PEM sin cifrar para generar el CSR del usuario"""
    datos = clave_privada_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(ruta, "wb") as f:
        f.write(datos)


def descifrar_nota(nota, usuario, contraseña):
    titulo, contenido_cifrado_b64, clave_aes_cifrada_b64, hmac_guardado = nota

    ruta_clave_privada = DIR_C + f"{usuario}/" + CLAVE_PRIVADA_C
    clave_privada_cifrada = leer_fichero_texto(ruta_clave_privada)

    try:
        # Descifrar clave privada RSA

        # Descifrar la clave privada que está en bytes PEM con AES-GCM
        clave_privada_bytes = descifrar_clave_privada(clave_privada_cifrada, contraseña)
        # Recuperar la clave privada RSA desde los bytes PEM descifrados (deserialización)
        clave_privada_obj = deserializar_clave_privada(clave_privada_bytes)

        # Descifrar clave AES con RSA privada
        clave_aes_cifrada_bytes = base64.b64decode(clave_aes_cifrada_b64)
        clave_aes = descifrar_RSA(clave_privada_obj, clave_aes_cifrada_bytes)

        # Descifrar contenido con AES
        contenido_descifrado = descifrar_texto(clave_aes, contenido_cifrado_b64)

        # Verificar HMAC
        if not verificar_hmac(clave_aes, contenido_cifrado_b64, hmac_guardado):
            return None, "HMAC inválido. Nota puede haber sido manipulada."
        
        else:
            print("HMAC verificado correctamente. Nota íntegra y auténtica.")
            print("\n--- RESULTADO DEL DESCIFRADO ---")
            print("Algoritmo simétrico: AES-GCM")
            print("Clave AES descifrada con RSA privada (2048 bits)")
            print("Longitud de la clave AES:", len(clave_aes), "bytes")
            print("Texto descifrado:", contenido_descifrado)
            print("-------------------------------\n")

        return titulo, contenido_descifrado

    except ValueError:
        print("ID de nota inválido")
    except Exception as e:
        print("Error al descifrar la nota:" + str(e))


def verificar_certificado(ruta_certificado, ruta_cadena_confianza):
    """Verifica si un certificado es válido contra la cadena de confianza."""
    print(f"\n==============================================")
    print(f"   VERIFICACIÓN DE CERTIFICADO DEL SERVIDOR")
    print("==============================================\n")
    
    comando_verificar = [
        "openssl", "verify", 
        "-CAfile", ruta_cadena_confianza, 
        ruta_certificado
    ]
    
    print(f"--- Verificamos contra la cadena de confianza ---")
    return ejecutar_comando_openssl(comando_verificar)


def leer_fichero_binario(ruta):
    """Lee el contenido del fichero en MODO BINARIO ('rb') y devuelve bytes."""
    with open(ruta, "rb") as f:
        datos = f.read()
    return datos


def escribir_fichero_binario(ruta, datos_bytes):
    """Escribe bytes en el fichero en MODO BINARIO ('wb')."""
    with open(ruta, "wb") as f:
        f.write(datos_bytes)


def leer_fichero_texto(ruta):
    """Lee el contenido del fichero en MODO TEXTO ('r') y devuelve un string."""
    with open(ruta, "r", encoding="utf-8") as f:
        datos = f.read()
    return datos


def escribir_fichero_texto(ruta, datos_str):
    """Escribe un string en el fichero en MODO TEXTO ('w')."""
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(datos_str)


def cifrar_fichero(ruta, contraseña):
    """
    Cifra bytes (raw key) usando AES-GCM.
    Devuelve un string base64 que contiene: salt + nonce + ciphertext
    """
    # 1. READ: Read the original data as bytes using BINARY mode
    datos = leer_fichero_binario(ruta) 
    salt = os.urandom(16) 

    # Derivar la contraseña
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    clave_aes = kdf.derive(contraseña.encode())

    # Cifrar con AES-GCM
    aesgcm = AESGCM(clave_aes)
    nonce = os.urandom(12) 
    ciphertext = aesgcm.encrypt(nonce, datos, None) # datos is correctly bytes

    # 2. ENCODE: Convert combined bytes (salt+nonce+ciphertext) to Base64 STRING
    datos_cifrados = base64.b64encode(salt + nonce + ciphertext).decode('utf-8')

    # 3. WRITE: Write the Base64 STRING using TEXT mode
    escribir_fichero_texto(ruta, datos_cifrados)
    return leer_fichero_texto(ruta)


def descifrar_fichero(ruta, contraseña):
    """
    Descifra un string base64 cifrado con AES-GCM usando clave derivada de contraseña.
    Devuelve los bytes originales.
    """
    # 1. READ: Read the Base64 STRING using TEXT mode
    datos_cifrados_str = leer_fichero_texto(ruta)
    
    # 2. DECODE: Convert Base64 STRING back to concatenated BYTES
    datos = base64.b64decode(datos_cifrados_str.encode('utf-8'))

    # Extraer salt, nonce y ciphertext
    salt = datos[:16]
    nonce = datos[16:28]  # 12 bytes
    ciphertext = datos[28:]

    # Derivar clave AES
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    clave_aes = kdf.derive(contraseña.encode())

    # Descifrar con AES-GCM
    aesgcm = AESGCM(clave_aes)
    datos_descifrados = aesgcm.decrypt(nonce, ciphertext, None) # Output is bytes

    # 3. WRITE: Write the decrypted BYTES (original key) using BINARY mode
    escribir_fichero_binario(ruta, datos_descifrados)
    return leer_fichero_texto(ruta)