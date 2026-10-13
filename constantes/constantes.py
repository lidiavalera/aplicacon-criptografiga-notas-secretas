# constantes/constantes.py
import os

# Directorio de Almacenamiento
DIR = "./ENTIDADES/"

# Directorio de la base de datos
DB_PATH = os.path.join(DIR, "usuarios_y_notas.db")

# --- DIRECTORIOS DEL PROGRAMA ---
DIR_R = DIR+"SSD_AC_Raiz/"
DIR_I = DIR+"SSD_AC_Intermedia/"
DIR_S = DIR+"SSD_Servidor/"
DIR_C = DIR+"SSD_Clientes/"

# --- CONSTANTES DE LA CA RAÍZ (R) ---
CLAVE_PRIVADA_R = DIR_R+"clave_privada_r.key"
CONFIGURACION_R = DIR_R+"config_r.cnf"
CERTIFICADO_R = DIR_R+"certificado_r.crt"

# --- CONSTANTES DE LA CA INTERMEDIA (I) ---
CLAVE_PRIVADA_I = DIR_I+"clave_privada_i.key"
CONFIGURACION_I = DIR_I+"config_i.cnf"
CERTIFICADO_I = DIR_I+"certificado_i.crt"
CSR_I = DIR_I+"solicitud_intermedia.csr"

# --- CONSTANTES SERVIDOR --- (S)
CLAVE_PRIVADA_S = DIR_S+"clave_privada_s.key"
CONFIGURACION_S = DIR_S+"config_s.cnf"
CERTIFICADO_S = DIR_S+"certificado_s.crt"
CSR_S = DIR_S+"solicitud_servidor.csr"

# --- NUEVAS CONSTANTES PARA USUARIOS ---
CLAVE_PRIVADA_C = "clave_privada_u.key"
CONFIGURACION_C = "config_u.cnf"
CSR_C = "solicitud_usuario.csr" 
CERTIFICADO_C = "certificado_usuario.crt"

# --- UBICACION DE CHAIN.pem ---
CHAIN_PATH = os.path.join(DIR, "chain.pem")