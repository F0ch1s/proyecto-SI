"""
  Permite que DOS personas chateen a traves de un bot de Telegram,
  pero con los mensajes CIFRADOS usando el algoritmo Feistel-X.
  Telegram solo transporta texto cifrado: nunca ve el mensaje real.

Como funciona:
  - Tu escribes un mensaje en la terminal.
  - El programa lo CIFRA con Feistel-X (cifrado.py de la Persona 1).
  - Envia el texto cifrado al bot, que lo reenvia a tu compañero.
  - El programa de tu compañero RECIBE el texto cifrado y lo DESCIFRA.

Como se usa (cada persona en su PC):
  1. Pon tu TOKEN, tu ID y el ID del otro mas abajo (seccion CONFIGURACION).
  2. Ejecuta:  python3 chat_telegram.py
  3. Escribe mensajes y presiona Enter. Escribe 'salir' para terminar.

IMPORTANTE:
  - Las dos personas usan el MISMO token (es el mismo bot).
  - Cada persona pone SU id en MI_ID y el id del otro en ID_DESTINO.
  - Ambos deben haberle dado /start al bot al menos una vez.
"""

import asyncio
import hashlib
from telegram import Bot
from telegram.request import HTTPXRequest

# Importamos el cifrado de la Persona 1
from cifrado import cifrar, descifrar


# ============================================================
# CONFIGURACION  — CADA PERSONA EDITA ESTAS 3 LINEAS
# ============================================================
# El token del bot (el mismo para los dos). Tapa esto con **** en el paper.
TOKEN = "8874725411:AAEmvqDfLV3Q1E-z1MNaey_aD6N7hr4s5WY"

# --- Si eres RODRIGO, deja esto asi: ---
MI_ID = 5841653022  # tu propio Chat ID
ID_DESTINO = 6191839605   # 

# --- Si eres PIERO, intercambia los numeros: ---
# MI_ID = 6191839605
# ID_DESTINO = 5841653022

# La clave secreta compartida del chat. Los dos DEBEN usar la misma.
# (Se deriva de una frase secreta acordada entre ambos.)
FRASE_SECRETA = "clave compartida del grupo SI"
CLAVE = hashlib.sha256(FRASE_SECRETA.encode()).digest()


# ============================================================
# FUNCIONES DE ENVIO Y RECEPCION
# ============================================================

async def enviar(bot, texto):
    """Cifra el texto y lo envia al compañero por Telegram."""
    cifrado = cifrar(texto, CLAVE)
    # Convertimos los bytes cifrados a texto hexadecimal para enviarlos.
    # Le ponemos una etiqueta para distinguir mensajes cifrados de otros.
    mensaje = "CIFRADO:" + cifrado.hex()
    await bot.send_message(chat_id=ID_DESTINO, text=mensaje)


async def escuchar(bot):
    """Revisa constantemente si llegaron mensajes nuevos y los descifra."""
    ultimo_update = 0
    while True:
        try:
            updates = await bot.get_updates(offset=ultimo_update + 1, timeout=10)
            for update in updates:
                ultimo_update = update.update_id
                if not update.message or not update.message.text:
                    continue
                # Solo procesamos los mensajes que vienen de nuestro compañero
                if update.message.chat_id != MI_ID:
                    continue
                texto = update.message.text
                if texto.startswith("CIFRADO:"):
                    # Quitamos la etiqueta y convertimos el hex de vuelta a bytes
                    hexa = texto[len("CIFRADO:"):]
                    datos = bytes.fromhex(hexa)
                    try:
                        original = descifrar(datos, CLAVE)
                        print(f"\n[Compañero] {original}")
                        print("[Tu] > ", end="", flush=True)
                    except Exception:
                        print("\n[!] Llego un mensaje que no se pudo descifrar.")
                        print("[Tu] > ", end="", flush=True)
        except Exception as e:
            # Si hay un error de red, esperamos un poco y reintentamos
            await asyncio.sleep(2)


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================

async def main():
    print("=" * 55)
    print("  CHAT CIFRADO POR TELEGRAM (Feistel-X)")
    print("=" * 55)
    print(f"[*] Tu ID: {MI_ID}  ->  Enviando a: {ID_DESTINO}")
    print(f"[*] Clave del chat: {CLAVE[:8].hex()}... (compartida por ambos)")
    print("[*] Los mensajes viajan CIFRADOS por Telegram.")
    print("[*] Escribe 'salir' para terminar.\n")

    # Creamos el bot con un tiempo de espera generoso para la red
    request = HTTPXRequest(connect_timeout=20, read_timeout=20)
    bot = Bot(token=TOKEN, request=request)

    # Limpiamos mensajes viejos para no leer historial atrasado
    try:
        updates = await bot.get_updates(timeout=1)
        if updates:
            await bot.get_updates(offset=updates[-1].update_id + 1, timeout=1)
    except Exception:
        pass

    # Lanzamos el "escuchador" en segundo plano
    tarea_escuchar = asyncio.create_task(escuchar(bot))

    # Bucle para escribir y enviar mensajes
    loop = asyncio.get_event_loop()
    while True:
        # input() es bloqueante; lo corremos en un hilo aparte para no congelar
        texto = await loop.run_in_executor(None, input, "[Tu] > ")
        if texto.lower() == "salir":
            break
        if texto.strip() == "":
            continue
        try:
            await enviar(bot, texto)
        except Exception as e:
            print(f"[!] Error al enviar: {e}")

    tarea_escuchar.cancel()
    print("[*] Chat cerrado.")


if __name__ == "__main__":
    asyncio.run(main())
