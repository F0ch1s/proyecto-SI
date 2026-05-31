"""
============================================================
  ESPIA (sniffer) — Demostracion de trafico cifrado
  Curso: Seguridad Informatica
  Persona 2 — Evidencia para la seccion de Resultados
============================================================

Que hace este archivo:
  Simula a un ATACANTE que intercepta la red entre el cliente y
  el servidor (un ataque de intermediario o "Man-in-the-Middle").
  Se coloca en medio, reenvia todo el trafico para que el chat
  siga funcionando, pero IMPRIME lo que realmente viaja por la red.

  Resultado: veras que el atacante NO puede leer los mensajes,
  solo ve bytes cifrados ilegibles. Eso demuestra que el cifrado
  protege la comunicacion.

Como se usa (necesitas 3 terminales):
  1. Terminal 1:  python3 servidor.py        (el servidor real)
  2. Terminal 2:  python3 espia.py           (el atacante en medio)
  3. Terminal 3:  python3 cliente_espia.py   (cliente que pasa por el espia)

  NOTA: para que el cliente pase por el espia, usa 'cliente_espia.py'
  (incluido mas abajo como instruccion) que se conecta al puerto 8888
  del espia en lugar de conectarse directo al servidor.

  Si prefieres no crear otro cliente, puedes cambiar temporalmente
  el PUERTO del cliente.py a 8888 y correr el espia.
"""

import socket
import threading

# El espia escucha aqui (donde se conectara el cliente)
ESPIA_HOST = "127.0.0.1"
ESPIA_PUERTO = 8888

# El servidor real esta aqui (a donde el espia reenvia)
SERVIDOR_HOST = "127.0.0.1"
SERVIDOR_PUERTO = 9999

contador = {"n": 0}


def mostrar_trafico(origen, datos):
    """Imprime en pantalla los bytes interceptados en hexadecimal."""
    contador["n"] += 1
    print("\n" + "=" * 60)
    print(f"  PAQUETE #{contador['n']}  interceptado  ({origen})")
    print("=" * 60)
    # Mostramos los bytes en hexadecimal (lo que ve el atacante)
    hexa = datos.hex()
    # partir en grupos para que se lea mejor
    grupos = " ".join(hexa[i:i+2] for i in range(0, len(hexa), 2))
    print(f"  Bytes que viajan por la red ({len(datos)} bytes):")
    print(f"  {grupos}")
    # Intentamos mostrarlo como texto (fallara: esta cifrado)
    try:
        texto = datos.decode("utf-8")
        print(f"  Como texto: {texto}")
    except Exception:
        print("  Como texto: [ILEGIBLE - los datos estan cifrados]")
    print("=" * 60)


def reenviar(origen_sock, destino_sock, etiqueta):
    """Lee datos de un lado, los muestra, y los reenvia al otro lado."""
    try:
        while True:
            datos = origen_sock.recv(4096)
            if not datos:
                break
            mostrar_trafico(etiqueta, datos)
            destino_sock.sendall(datos)  # reenviar para que el chat funcione
    except Exception:
        pass
    finally:
        origen_sock.close()
        destino_sock.close()


def main():
    print("=" * 60)
    print("  ESPIA / SNIFFER — Interceptando trafico de red")
    print("=" * 60)
    print(f"[*] Escuchando en {ESPIA_HOST}:{ESPIA_PUERTO}")
    print(f"[*] Reenviando al servidor real en {SERVIDOR_HOST}:{SERVIDOR_PUERTO}")
    print("[*] Esperando que el cliente se conecte a traves mio...\n")

    espia = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    espia.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    espia.bind((ESPIA_HOST, ESPIA_PUERTO))
    espia.listen(1)

    conn_cliente, addr = espia.accept()
    print(f"[+] Cliente interceptado desde {addr}")

    # El espia se conecta al servidor real
    conn_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_servidor.connect((SERVIDOR_HOST, SERVIDOR_PUERTO))
    print("[+] Conectado al servidor real. Reenviando trafico...\n")

    # Dos hilos: uno para cada direccion del trafico
    t1 = threading.Thread(target=reenviar,
                          args=(conn_cliente, conn_servidor, "CLIENTE -> SERVIDOR"),
                          daemon=True)
    t2 = threading.Thread(target=reenviar,
                          args=(conn_servidor, conn_cliente, "SERVIDOR -> CLIENTE"),
                          daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print("\n[*] Conexion terminada.")


if __name__ == "__main__":
    main()
