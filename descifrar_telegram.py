"""
============================================================
  DESCIFRAR MENSAJE DE TELEGRAM (herramienta manual)
  Curso: Seguridad Informatica
  Persona 2 — Demostracion de descifrado
============================================================

Para que sirve:
  Demuestra que un mensaje cifrado que viajo por Telegram
  (el texto "CIFRADO:7a3f9b...") se puede descifrar y recuperar
  el mensaje original, usando la clave compartida.

Como se usa:
  1. Copia del chat del bot el texto cifrado (empieza con CIFRADO:).
  2. Ejecuta:  python3 descifrar_telegram.py
  3. Pega el texto cuando te lo pida y presiona Enter.
  4. Te muestra el mensaje original descifrado.
"""

import hashlib
from cifrado import cifrar, descifrar

# La MISMA clave que usan en el chat (la frase secreta compartida)
FRASE_SECRETA = "clave compartida del grupo SI"
CLAVE = hashlib.sha256(FRASE_SECRETA.encode()).digest()

PREFIJO = "CIFRADO:"


def main():
    print("=" * 55)
    print("  DESCIFRADOR DE MENSAJES DE TELEGRAM (Feistel-X)")
    print("=" * 55)
    print("Pega el texto cifrado del chat (empieza con 'CIFRADO:').")
    print("Escribe 'salir' para terminar.\n")

    while True:
        entrada = input("Texto cifrado > ").strip()
        if entrada.lower() == "salir":
            break
        if entrada == "":
            continue

        # Quitar el prefijo si lo tiene
        if entrada.startswith(PREFIJO):
            hexa = entrada[len(PREFIJO):]
        else:
            hexa = entrada

        try:
            datos = bytes.fromhex(hexa)
            original = descifrar(datos, CLAVE)
            print(f"  --> Mensaje original: {original}\n")
        except ValueError:
            print("  [!] Eso no parece un texto cifrado valido (revisa que copiaste bien).\n")
        except Exception:
            print("  [!] No se pudo descifrar (¿la clave es la misma que al cifrar?).\n")


if __name__ == "__main__":
    main()
