# cliente/interfaz_usuario.py
from servidor.gestion_notas import crear_nota, listar_notas, leer_nota
from servidor.autenticacion import comprobar_contraseña
from .criptografia_cliente import descifrar_nota
from servidor.base_datos import eliminar_nota

def pedir_login():
    usuario = input("Escriba su nombre de usuario: ").strip()
    contraseña = input("Escriba su contraseña: ").strip()
    return usuario, contraseña


def pedir_registro():
    usuario = input("Elija un nombre de usuario: ").strip()
    email = input("Escriba su email: ").strip()
    contraseña = input("Elija una contraseña: ").strip()
    confirmar = input("Confirme la contraseña: ").strip()
    return usuario, email, contraseña, confirmar


def menu_usuario():
    print("\n¿Qué función desea utilizar?")
    print("1. Crear una nota secreta.")
    print("2. Ver mis notas.")
    print("3. Leer una nota secreta.")
    print("4. Eliminar nota.")
    print("5. Salir.")
    return input("Seleccione una opción: ").strip()


def pedir_datos_nota():
    titulo = input("¿Cuál es el título de la nota?: ").strip()
    print("Escriba su nota (pulsa Enter para finalizar):")
    contenido = input()
    return titulo, contenido


def pedir_confirmacion():
    respuesta = input("¿Quiere guardar la nota? (s/n): ").strip().lower()
    return respuesta == 's'


def pedir_id_nota():
    num = input("Introduzca el ID de la nota que quieras seleccionar: ").strip()
    try:
        return int(num)
    except ValueError:
        return None


def ejecutar_menu(usuario, id_usuario: int):
    while True:
        opcion = menu_usuario()

        if opcion == "1":
            titulo, contenido = pedir_datos_nota()
            confirmar= pedir_confirmacion()
            if not confirmar:
                print("Nota no guardada.")
                continue
            correcto = crear_nota(id_usuario, titulo, contenido)
            if correcto:
                print("Nota creada y guardada correctamente.")
            else:
                print("Error al crear la nota.")

        elif opcion == "2":
            notas = listar_notas(id_usuario)
            if not notas:
                print("No tienes notas guardadas.")
            else:
                print("\nTus notas:")
                for num, titulo in notas:
                    print( num, ".", titulo )

        elif opcion == "3":
            nota_id = pedir_id_nota()
            if nota_id is None:
                print("ID inválido.")
                continue
            # Solicitar contraseña para descifrar clave privada
            contraseña = input("Introduce tu contraseña para descifrar la nota: ")
            resultado = comprobar_contraseña(id_usuario, contraseña)
            if resultado is None:
                print("Error: contraseña incorrecta.")
                continue
            
            # Le pedimos al servidor la nota y nos la devuelve cifrada
            nota_cifrada = leer_nota(id_usuario, nota_id)
            if nota_cifrada is None:
                print("No se ha encontrado la nota")
                continue

            nota= descifrar_nota(nota_cifrada, usuario, contraseña)
            titulo, contenido = nota
            print(f"\n--- {titulo} ---")
            print(contenido)
            print("-------------------\n")

        elif opcion == "4":
            print("\nMenú de eliminación de notas, si no desea eliminar ninguna nota, pulse Enter sin escribir nada")
            nota_id = pedir_id_nota()
            if nota_id is None:
                print("ID inválido.")
                continue

            # Solicitar contraseña para descifrar clave privada
            contraseña = input("Introduce tu contraseña para eliminar la nota: ")
            resultado = comprobar_contraseña(id_usuario, contraseña)
            if resultado is None:
                print("Error: contraseña incorrecta.")
                continue
            eliminar_nota(nota_id, id_usuario)
            print("Nota eliminada con éxito")


        elif opcion == "5":
            print("Saliendo al menú de usuario.")
            break

        else:
            print("Opción inválida, inténtelo de nuevo.")

