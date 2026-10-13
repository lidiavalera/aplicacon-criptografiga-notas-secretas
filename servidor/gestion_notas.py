# servidor/gestion_notas.py
from .base_datos import guardar_notas, coger_todas_las_notas, coger_una_nota, extraer_certificado_usuario, eliminar_nota
from .criptografia import cifrar_notas, extraer_clave_publica_certificado

import base64

def crear_nota(usuario_id: int, titulo: str, nota: str) -> bool:
    """
    Cifra una nota usando la clave pública del usuario y guarda en BD.
    Devuelve True si todo fue correcto.
    """
    certificado = extraer_certificado_usuario(usuario_id)
    if certificado is None:
        return False
    print(certificado)
    clave_publica= extraer_clave_publica_certificado(certificado)

    nota_cifrada, clave_aes_cifrada, hmac_etiqueta = cifrar_notas(nota, clave_publica)
    print("\n--- RESULTADO DEL CIFRADO ---")
    print("Algoritmo simétrico: AES-GCM")
    print("Algoritmo asimétrico: RSA (2048 bits, OAEP-SHA256)")
    print("Longitud de clave AES:", len(base64.b64decode(clave_aes_cifrada)), "bytes (cifrada con RSA)")
    print("Nota cifrada (base64):", nota_cifrada)
    print("-------------------------------\n")
    # Guardar en base de datos
    guardar_notas(usuario_id, titulo, nota_cifrada, clave_aes_cifrada, hmac_etiqueta)
    
    return True

# Eliminar nota directamente en DB


def listar_notas(usuario_id: int):
    """
    Devuelve lista de tuplas (id, titulo) para mostrar en cliente.
    """
    notas = coger_todas_las_notas(usuario_id)
    # notas: [(id, titulo, contenido, clave_aes_cifrada, hmac), ...]
    if not notas:
        return []
    else:
        resultado = []
        for n in notas:
            resultado.append( (n[0], n[1]) )
    return resultado


def leer_nota(usuario_id: int, nota_id: int):
    """
    Descifra y devuelve el contenido en texto claro.
    Se requiere la contraseña del usuario para descifrar su clave privada.
    Retorna (titulo, texto_descifrado) o (None, mensaje_error)
    """
    nota = coger_una_nota(nota_id, usuario_id)
    if not nota:
        return None

    return nota
