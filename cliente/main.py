# cliente/main.py
from servidor.autenticacion import inicio_sesion, registrarse
from servidor.base_datos import crear_tablas
from servidor.pki import *
from .interfaz_usuario import pedir_login, pedir_registro, ejecutar_menu
from .criptografia_cliente import *
import re
import shutil
from pathlib import Path

def main():

    # Creamos todos los directorios que vamos a usar en el proyecto
    Path(DIR_R).mkdir(parents=True, exist_ok=True)
    Path(DIR_I).mkdir(parents=True, exist_ok=True)
    Path(DIR_S).mkdir(parents=True, exist_ok=True)
    Path(DIR_C).mkdir(parents=True, exist_ok=True)

    crear_tablas()
    crear_ac_raiz()
    crear_ac_intermedia()
    chain_file = crear_cadena_confianza()
    crear_certificado_servidor()

    print("\n\n\n***Esta ejecución se asume por un canal de comunicación seguro de clave simétrica acordada con TLS***")
    print("La conexión realizada es entre el cliente y el presunto servidor de nuestra aplicación")

    
    # Si no es válido cerramos el programa directamente
    if not verificar_certificado(CERTIFICADO_S, chain_file):
        print("No se ha podido verificar la veracidad del servidor, cerrando conexión")
        return -1
    
    print("\n\n===--- Servidor verificado con éxito, completando el acceso... ---===\n\n")
    print("Bienvenido a la aplicación de notas secretas")
    

    while True:
        print("\n1. Iniciar sesión")
        print("2. Registrarse")
        print("3. Salir")
        opcion = input("Seleccione una opción: ").strip()

        if opcion == "1":
            usuario, contraseña = pedir_login()
            id_usuario = inicio_sesion(usuario, contraseña)
            if id_usuario is not None:
                print("Sesión iniciada correctamente (usuario_id =",id_usuario,")")
                ejecutar_menu(usuario, id_usuario)
            else:
                print("Error: usuario o contraseña incorrectos.")

        elif opcion == "2":
            usuario, email, contraseña, confirmar = pedir_registro()
            if contraseña != confirmar:
                print("Las contraseñas no coinciden. Intentelo de nuevo.")
                continue

            # Validar seguridad de la contraseña
            mayusculas = re.search(r"[A-Z]", contraseña)
            minusculas = re.search(r"[a-z]", contraseña)
            digitos = re.search(r"[0-9]", contraseña)
            especiales = re.search(r"[^a-zA-Z0-9\s]", contraseña)

            # Verificamos que se cumplan todos los requisitos
            if not (mayusculas and minusculas and digitos and especiales and len(contraseña) >= 8):
                print("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
                continue

            # Creamos la carpeta del usuario para guardar sus datos de manera aislada
            carp_usuario = DIR_C + f"{usuario}/"
            Path(carp_usuario).mkdir(parents=True, exist_ok=True)

            # Generamos en la carpeta nueva la clave privada RSA (2048 bits) del usuario
            ruta_priv = os.path.join(carp_usuario, CLAVE_PRIVADA_C)
            clave_privada = generar_clave_cliente()
            clave_privada_serializada = serializar_clave_privada(clave_privada)
            escribir_fichero_binario(ruta_priv, clave_privada_serializada)

            # La usamos inmediatamente para generar el certificado haciendo uso de la pki
            ruta_certificado = crear_certificado_usuario(usuario, email, carp_usuario)

            with open(ruta_certificado, "r") as f:
                certificado = f.read()

            # Ciframos la clave privada para mayor seguridad usando un passphrase
            cifrar_fichero(ruta_priv, contraseña)

            correcto = registrarse(usuario, email, contraseña, certificado)
            if correcto:
                print("Usuario registrado correctamente. Inicie sesión.")
            else:
                print("No se pudo registrar, el usuario ya existe.")
                continue

        elif opcion == "3":
            print("Saliendo del programa...")
            break

        elif opcion == "100":
            print("\nSe ha seleccionado la opción de desarrollador")
            print("Borrando todos los ficheros y restableciendo el programa a su estado original...")
            print("*** DISCLAIMER ***")
            print("Esta opción no está destinada para el usuario, no es una opción disponible para éste\n")
            if os.path.exists(DIR):
                shutil.rmtree(DIR)
            break

        else:
            print("Opción inválida. Intente de nuevo.")

if __name__ == "__main__":
    main()