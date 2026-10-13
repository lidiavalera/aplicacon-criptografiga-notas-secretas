# servidor/criptografia.py
import os
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509


# instalar la libreria cryptography poniendo en la terminal: pip install cryptography


# FUNCIONES DE HASH Y CONTRASEÑAS

def generar_hash(contraseña):
    """
    Genera un hash seguro para una contraseña usando PBKDF2 + SHA256 + salt aleatorio.
    Devuelve un string en base64 que contiene salt + hash.
    """
    salt = os.urandom(16)  # Salt aleatorio de 16 bytes (128 bits)
    
    # Configuración de PBKDF2 con SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # Hash de 32 bytes (256 bits)
        salt=salt,
        iterations=100000,  # Más iteraciones = más seguro
        backend=default_backend()
    )
    
    key = kdf.derive(contraseña.encode('utf-8'))  # Convertimos contraseña a bytes y derivamos hash
    
    # Concatenamos salt + hash y codificamos en base64 para almacenar como string
    return base64.b64encode(salt + key).decode('utf-8')


def verificar_contraseña(contraseña_introducida, hash_guardado):
    """
    Verifica si la contraseña introducida coincide con el hash almacenado.
    """
    data = base64.b64decode(hash_guardado.encode('utf-8'))  # Decodificar base64
    salt = data[:16]       # Extraer salt (primeros 16 bytes)
    hash_guardado = data[16:]  # Extraer hash real (los 32 bytes siguientes)

    # Reconstruimos el KDF con el mismo salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    try:
        kdf.verify(contraseña_introducida.encode('utf-8'), hash_guardado)  # Verifica si coinciden
        return True
    except Exception:
        return False


# FUNCIONES DE CIFRADO SIMÉTRICO (AES-GCM)

def generar_clave_aes():
    """Genera una clave aleatoria AES-256 (32 bytes)."""
    return AESGCM.generate_key(bit_length=256) #longitud_clave= 32 bytes porque es el mayor tamaño que permite AES-GCM y el más seguro.


def cifrar_texto_AES(clave, texto):
    """Cifra texto con AES-GCM y devuelve base64 (nonce + ciphertext)."""
    aesgcm = AESGCM(clave) # Crear un objeto AES-GCM con la clave proporcionada.
    nonce = os.urandom(12)  # Generamos un nonce de 96 bits (12 bytes), recomendado por NIST. Este valor es necesario para usar AES-GCM y garantiza que cada cifrado con la misma clave sea único.
    texto_bytes = texto.encode('utf-8') # Convertimos el texto a bytes, porque AES trabaja con bytes.
    ciphertext = aesgcm.encrypt(nonce, texto_bytes, None) # Ciframos el texto con AES-GCM. El tercer parámetro es para datos adicionales autenticados (AAD), que no usamos aquí.
    resultado = base64.b64encode(nonce + ciphertext).decode('utf-8') # Concatenar nonce + ciphertext y codificar todo en base64 para poder almacenarlo
    print(f"Cifrado AES-GCM aplicado. Longitud clave: {len(clave)} bytes")
    return resultado


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


# FUNCIONES DE CIFRADO ASIMÉTRICO (RSA)

def generar_par_claves():
    """Genera un par de claves RSA (privada y pública)"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


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


def cifrar_RSA(clave_publica, clave_aes):
    """Cifra la clave_aes con la clave pública RSA usando OAEP+SHA256, recomendado y estándar para cifrado RSA según NIST"""
    cifrado = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cifrado  # bytes


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


# FUNCIONES DE HMAC (AUTENTICACIÓN DE MENSAJES)

def generar_hmac(clave, mensaje):
    """Genera HMAC SHA256 para autenticación del mensaje"""
    h = hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256)
    etiqueta = h.hexdigest()
    print("HMAC generado (SHA256):" + str(etiqueta))
    return etiqueta


def verificar_hmac(clave, mensaje, etiqueta_esperada):
    """Verifica la autenticidad del mensaje mediante HMAC"""
    h = hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256)
    etiqueta_calculada = h.hexdigest()
    
    if hmac.compare_digest(etiqueta_calculada, etiqueta_esperada):
        print(f"HMAC verificado correctamente con clave de {len(clave)} bytes y algoritmo SHA256.")
        return True
    else:
        print("Error: HMAC no coincide - Posible manipulación del mensaje")
        return False


# FUNCIONES DE SERIALIZACIÓN DE CLAVES

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


# CIFRADO HÍBRIDO (AES + RSA) PARA NOTAS

def cifrar_notas(nota, clave_publica):
    """
    Cifra un texto de nota usando cifrado híbrido:
    - AES simétrico para el contenido
    - RSA asimétrico para la clave AES
    - HMAC para autenticidad
    """
    print("Aplicando cifrado híbrido (AES + RSA)...")
    print("Algoritmo simétrico: AES-GCM.")
    print("Algoritmo asimétrico: RSA (2048 bits, OAEP + SHA256).")
    # Generar clave AES aleatoria para esta nota
    clave_aes = generar_clave_aes()
    print(f"Clave AES generada: {base64.b64encode(clave_aes).decode('utf-8')}")
    
    # Cifrar el contenido de la nota con AES
    texto_cifrado_b64 = cifrar_texto_AES(clave_aes, nota)
    
    # Cifrar la clave AES con RSA pública del usuario
    clave_aes_cifrada = cifrar_RSA(clave_publica, clave_aes)
    clave_aes_cifrada_b64 = base64.b64encode(clave_aes_cifrada).decode()
    print("Clave AES cifrada con RSA pública del usuario")
    
    # Generar HMAC de autenticidad usando la clave AES
    hmac_etiqueta = generar_hmac(clave_aes, texto_cifrado_b64)

    print("Cifrado híbrido completado. Nota cifrada lista para almacenar.\n")
    return texto_cifrado_b64, clave_aes_cifrada_b64, hmac_etiqueta


def extraer_clave_publica_certificado(certificado):
    """devuelve un objeto clave pública, NO un PEM"""
    cert = x509.load_pem_x509_certificate(certificado.encode())
    return cert.public_key()