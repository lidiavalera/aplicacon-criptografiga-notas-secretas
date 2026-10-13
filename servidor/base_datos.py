# servidor/base_datos.py
import sqlite3
import os
from constantes.constantes import DB_PATH

def conectar():
    #Crea una ruta a mi base de datos.
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) # Esto hace que si la carpeta ya existe, no lance un error, simplemente continúa.
    #Conecta con mi base de datos.
    return sqlite3.connect(DB_PATH)


def crear_tablas():
    conexion = conectar()
    cursor = conexion.cursor()

    #TABLA USUARIOS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            contraseña TEXT NOT NULL,
            certificado TEXT NOT NULL
        )
    """)

    #TABLA NOTAS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            titulo TEXT NOT NULL,
            contenido TEXT NOT NULL,
            clave_aes_cifrada TEXT NOT NULL,
            hmac TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    """)

    conexion.commit() #Guarda los cambios.
    conexion.close() #Se cierrar la conexión, para liberar memoria y evitar bloqueos.


def guardar_notas(usuario_id, titulo, nota_cifrada, clave_aes_cifrada, hmac_etiqueta):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute(" INSERT INTO notas (usuario_id, titulo, contenido, clave_aes_cifrada, hmac) VALUES (?, ?, ?, ?, ?)", (usuario_id, titulo, nota_cifrada, clave_aes_cifrada, hmac_etiqueta))
    conexion.commit()
    conexion.close()


def coger_todas_las_notas(usuario_id):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("SELECT id, titulo, contenido, clave_aes_cifrada, hmac FROM notas WHERE usuario_id = ?", (usuario_id,))
    notas = cursor.fetchall()
    conexion.close()
    return notas


def coger_una_nota(nota_id, usuario_id):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("SELECT  titulo, contenido, clave_aes_cifrada, hmac FROM notas WHERE id = ? AND usuario_id = ?", (nota_id,usuario_id))
    nota = cursor.fetchone()
    conexion.close()
    return nota


def eliminar_nota(nota_id, usuario_id):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM notas where id = ? AND usuario_id = ?", (nota_id,usuario_id))
    conexion.commit()
    conexion.close()


def insertar_usuario(nombre, email, hash_contraseña, certificado):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO usuarios (nombre, email, contraseña, certificado) VALUES (?, ?, ?, ?)", (nombre, email, hash_contraseña, certificado))
    conexion.commit()
    # Obtener el id del nuevo usuario
    cursor.execute("SELECT id FROM usuarios WHERE nombre = ?", (nombre,))
    usuario_id = cursor.fetchone()[0]
    conexion.close()
    return usuario_id


def existe_usuario(nombre):
    conexion = conectar()
    cursor = conexion.cursor()
    # Verificamos si el usuario ya existe
    cursor.execute("SELECT id FROM usuarios WHERE nombre = ?", (nombre,))
    #.fetchone() devuelve None si no hay resultados, y si hay devuelve la primera fila de la tabla.
    fila = cursor.fetchone()
    conexion.close()
    return fila


def nombre_id(id_usuario):
    conexion = conectar()
    cursor = conexion.cursor()
    # Verificamos si el usuario ya existe
    cursor.execute("SELECT nombre FROM usuarios WHERE id = ?", (id_usuario,))
    #.fetchone() devuelve None si no hay resultados, y si hay devuelve la primera fila de la tabla.
    fila = cursor.fetchone()
    conexion.close()
    return fila


def obtener_hash_usuario(nombre):
    # Conectar a la base de datos
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("SELECT id, contraseña FROM usuarios WHERE nombre = ?", (nombre,))
    #.fetchone() devuelve None si no hay resultados, y si hay devuelve la primera fila de la tabla.
    fila = cursor.fetchone()
    #Terminamos la conexión con la base de datos
    conexion.close()
    return fila  # (id, hash) o None


def obtener_solo_contraseña(id):
    # Conectar a la base de datos
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("SELECT contraseña FROM usuarios WHERE id = ?", (id,))
    #.fetchone() devuelve None si no hay resultados, y si hay devuelve la primera fila de la tabla.
    fila = cursor.fetchone()
    #Terminamos la conexión con la base de datos
    conexion.close()
    return fila  # (hash de la contraseña) o None


def extraer_certificado_usuario(id_usuario):
    conexion = conectar()
    cursor = conexion.cursor()
    cursor.execute("SELECT certificado FROM usuarios WHERE id = ?", (id_usuario,))
    #.fetchone() devuelve None si no hay resultados, y si hay devuelve la primera fila de la tabla.
    certificado = cursor.fetchone()[0]
    conexion.close()
    return certificado