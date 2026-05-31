"""
============================================================
  SERVIDOR — Chat cifrado cliente/servidor
  Curso: Seguridad Informatica
  Persona 2 — Aplicacion telematica
============================================================

Que hace este archivo:
  Espera a que un cliente se conecte. Cuando se conecta:
    1. Acuerdan una clave secreta con Diffie-Hellman (sin enviarla).
    2. A partir de ahi, TODOS los mensajes viajan cifrados con
       el algoritmo Feistel-X (archivo cifrado.py de la Persona 1).

Como se usa:
  Abre una terminal en esta carpeta y ejecuta:
      python servidor.py
  Luego, en OTRA terminal, ejecuta el cliente:
      python cliente.py
  Escribe mensajes y presiona Enter. Escribe 'salir' para terminar.
"""

import socket      # para la conexion de red (sockets TCP)
import threading   # para enviar y recibir al mismo tiempo
import struct      # para empaquetar la longitud de cada mensaje
import hashlib     # para convertir el secreto compartido en clave
import random      # para generar la clave privada de Diffie-Hellman

# Importamos las funciones de cifrado de la Persona 1
from cifrado import cifrar, descifrar


# ============================================================
# CONFIGURACION
# ============================================================
HOST = "127.0.0.1"   # localhost = la misma PC. Para 2 PCs, ver nota al final.
PUERTO = 9999        # un puerto libre cualquiera


# ============================================================
# DIFFIE-HELLMAN (intercambio de clave secreta)
# ============================================================
# Permite que servidor y cliente acuerden la MISMA clave secreta
# sin enviarla nunca por la red. Un espia que vea todo el trafico
# no puede calcular la clave.

# Numeros publicos (los pueden conocer todos). P es un primo grande.
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
DH_G = 2


def dh_generar_privada():
    """Genera un numero secreto aleatorio (la clave privada)."""
    return random.randint(2, DH_P - 2)


def dh_clave_publica(privada):
    """Calcula la clave publica a partir de la privada: G^privada mod P"""
    return pow(DH_G, privada, DH_P)


def dh_secreto_compartido(publica_del_otro, mi_privada):
    """Calcula el secreto compartido y lo convierte en clave de 32 bytes."""
    secreto = pow(publica_del_otro, mi_privada, DH_P)
    return hashlib.sha256(secreto.to_bytes(32, "big")).digest()


# ============================================================
# FUNCIONES PARA ENVIAR Y RECIBIR MENSAJES
# ============================================================
# Cada mensaje se envia asi: primero 4 bytes que dicen el tamaño,
# y luego el mensaje cifrado. Asi el otro lado sabe cuanto leer.

def enviar_mensaje(sock, clave, texto):
    """Cifra el texto y lo envia por el socket."""
    cifrado = cifrar(texto, clave)
    longitud = struct.pack(">I", len(cifrado))  # 4 bytes con el tamaño
    sock.sendall(longitud + cifrado)


def recibir_exacto(sock, n):
    """Recibe exactamente n bytes (los sockets pueden llegar partidos)."""
    buffer = b""
    while len(buffer) < n:
        parte = sock.recv(n - len(buffer))
        if not parte:
            raise ConnectionError("Conexion cerrada")
        buffer += parte
    return buffer


def recibir_mensaje(sock, clave):
    """Recibe un mensaje cifrado del socket y lo descifra."""
    raw_len = recibir_exacto(sock, 4)            # leer los 4 bytes del tamaño
    tam = struct.unpack(">I", raw_len)[0]        # convertir a numero
    cifrado = recibir_exacto(sock, tam)          # leer el mensaje cifrado
    return descifrar(cifrado, clave)             # descifrar y devolver texto


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

def main():
    print("=" * 50)
    print("  SERVIDOR DE CHAT CIFRADO (Feistel-X)")
    print("=" * 50)

    # Crear el socket y ponerlo a escuchar
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PUERTO))
    servidor.listen(1)
    print(f"[*] Escuchando en {HOST}:{PUERTO} ...")
    print("[*] Esperando que el cliente se conecte...\n")

    conn, direccion = servidor.accept()
    print(f"[+] Cliente conectado desde {direccion}")

    # ---- HANDSHAKE DIFFIE-HELLMAN ----
    mi_privada = dh_generar_privada()
    mi_publica = dh_clave_publica(mi_privada)

    # Recibir la clave publica del cliente (32 bytes)
    publica_cliente = int.from_bytes(recibir_exacto(conn, 32), "big")
    # Enviar nuestra clave publica
    conn.sendall(mi_publica.to_bytes(32, "big"))

    # Calcular la clave secreta compartida
    clave = dh_secreto_compartido(publica_cliente, mi_privada)
    print(f"[+] Clave secreta establecida: {clave[:8].hex()}... (no se envio por la red)")
    print("[*] Ya pueden chatear. Escribe 'salir' para terminar.\n")

    # ---- HILO QUE RECIBE MENSAJES EN SEGUNDO PLANO ----
    def escuchar():
        while True:
            try:
                msg = recibir_mensaje(conn, clave)
                print(f"\n[Cliente] {msg}")
                print("[Tu] > ", end="", flush=True)
            except Exception:
                print("\n[!] El cliente se desconecto.")
                break

    threading.Thread(target=escuchar, daemon=True).start()

    # ---- BUCLE PARA ENVIAR MENSAJES ----
    while True:
        texto = input("[Tu] > ")
        if texto.lower() == "salir":
            break
        try:
            enviar_mensaje(conn, clave, texto)
        except Exception:
            print("[!] Error al enviar el mensaje.")
            break

    conn.close()
    servidor.close()
    print("[*] Servidor cerrado.")


if __name__ == "__main__":
    main()


# ============================================================
# NOTA: ¿Como probar entre DOS PCs distintas? (opcional)
# ============================================================
# 1. En el servidor, cambia HOST = "0.0.0.0" (acepta conexiones de afuera).
# 2. Averigua la IP local del servidor (ej: 192.168.1.50).
# 3. En cliente.py, pon esa IP en la variable HOST.
# Ambas PCs deben estar en la misma red WiFi/LAN.
