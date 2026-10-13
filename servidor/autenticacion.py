# servidor/autenticacion.py
from .base_datos import existe_usuario, insertar_usuario, obtener_hash_usuario, obtener_solo_contraseña
from .criptografia import generar_hash, verificar_contraseña

def registrarse(nombre: str, email:str, contraseña: str, certificado) -> bool:
    """
    Registra un usuario. Devuelve True si correcto, False si falla (usuario ya existe, etc).
    """
    # Verificamos si el usuario ya existe
    if existe_usuario(nombre) is not None:
        return False

    # Generar hash de la contraseña y almacenar usuario
    hash_contraseña = generar_hash(contraseña)
    insertar_usuario(nombre, email, hash_contraseña, certificado)

    return True


def inicio_sesion(nombre: str, contraseña: str):
    """
    Verifica que el nombre y la contraseña existan en la base de datos y sean correctos. Devuelve id_usuario (int) si correcto, None si incorrecto.
    """
    fila = obtener_hash_usuario(nombre)
    if not fila:
        return None
    usuario_id, hash_guardado = fila
    if verificar_contraseña(contraseña, hash_guardado):
        return usuario_id
    return None


def comprobar_contraseña(id: str, contraseña: str):
    """
    Verifica que la contraseña del usuario sea correcta. Devuelve id_usuario (int) si correcto, None si incorrecto.
    """
    fila = obtener_solo_contraseña(id)
    if not fila:
        return None
    hash_guardado = fila[0]
    if verificar_contraseña(contraseña, hash_guardado):
        return id
    return None