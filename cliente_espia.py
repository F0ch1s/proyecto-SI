"""
============================================================
  CLIENTE — Chat cifrado cliente/servidor
  Curso: Seguridad Informatica
  Persona 2 — Aplicacion telematica
============================================================

Que hace este archivo:
  Se conecta al servidor. Al conectarse:
    1. Acuerdan una clave secreta con Diffie-Hellman (sin enviarla).
    2. A partir de ahi, TODOS los mensajes viajan cifrados con
       el algoritmo Feistel-X (archivo cifrado.py de la Persona 1).

Como se usa:
  PRIMERO ejecuta el servidor en una terminal:
      python servidor.py
  LUEGO, en otra terminal, ejecuta este cliente:
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
HOST = "127.0.0.1"   # localhost = la misma PC. Debe coincidir con el servidor.
PUERTO = 8888        # pasa por el espia, no directo al servidor        # el mismo puerto que usa el servidor


# ============================================================
# DIFFIE-HELLMAN (intercambio de clave secreta)
# ============================================================
# Mismos numeros publicos que el servidor (tienen que coincidir).
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

def enviar_mensaje(sock, clave, texto):
    """Cifra el texto y lo envia por el socket."""
    cifrado = cifrar(texto, clave)
    longitud = struct.pack(">I", len(cifrado))
    sock.sendall(longitud + cifrado)


def recibir_exacto(sock, n):
    """Recibe exactamente n bytes."""
    buffer = b""
    while len(buffer) < n:
        parte = sock.recv(n - len(buffer))
        if not parte:
            raise ConnectionError("Conexion cerrada")
        buffer += parte
    return buffer


def recibir_mensaje(sock, clave):
    """Recibe un mensaje cifrado del socket y lo descifra."""
    raw_len = recibir_exacto(sock, 4)
    tam = struct.unpack(">I", raw_len)[0]
    cifrado = recibir_exacto(sock, tam)
    return descifrar(cifrado, clave)


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

def main():
    print("=" * 50)
    print("  CLIENTE DE CHAT CIFRADO (Feistel-X)")
    print("=" * 50)

    # Conectarse al servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] Conectando a {HOST}:{PUERTO} ...")
    sock.connect((HOST, PUERTO))
    print("[+] Conectado al servidor.")

    # ---- HANDSHAKE DIFFIE-HELLMAN ----
    mi_privada = dh_generar_privada()
    mi_publica = dh_clave_publica(mi_privada)

    # Enviar nuestra clave publica primero
    sock.sendall(mi_publica.to_bytes(32, "big"))
    # Recibir la clave publica del servidor
    publica_servidor = int.from_bytes(recibir_exacto(sock, 32), "big")

    # Calcular la clave secreta compartida
    clave = dh_secreto_compartido(publica_servidor, mi_privada)
    print(f"[+] Clave secreta establecida: {clave[:8].hex()}... (no se envio por la red)")
    print("[*] Ya pueden chatear. Escribe 'salir' para terminar.\n")

    # ---- HILO QUE RECIBE MENSAJES EN SEGUNDO PLANO ----
    def escuchar():
        while True:
            try:
                msg = recibir_mensaje(sock, clave)
                print(f"\n[Servidor] {msg}")
                print("[Tu] > ", end="", flush=True)
            except Exception:
                print("\n[!] El servidor se desconecto.")
                break

    threading.Thread(target=escuchar, daemon=True).start()

    # ---- BUCLE PARA ENVIAR MENSAJES ----
    while True:
        texto = input("[Tu] > ")
        if texto.lower() == "salir":
            break
        try:
            enviar_mensaje(sock, clave, texto)
        except Exception:
            print("[!] Error al enviar el mensaje.")
            break

    sock.close()
    print("[*] Cliente cerrado.")


if __name__ == "__main__":
    main()
