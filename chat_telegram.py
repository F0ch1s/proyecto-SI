"""
  Permite que DOS personas chateen a traves de un bot de Telegram,
  pero con los mensajes CIFRADOS usando el algoritmo Feistel-X.
  Telegram solo transporta texto cifrado: nunca ve el mensaje real.

Como funciona:
  - Tu escribes un mensaje en la terminal.
  - El programa lo CIFRA con Feistel-X (cifrado.py de la Persona 1).
  - Envia el texto cifrado al bot, que lo reenvia a tu compañero.
  - El programa de tu compañero RECIBE el texto cifrado y lo DESCIFRA.
  - En Telegram puedes escribir "descifrar" (o "descifrar" + hex) para
    descifrar el ultimo mensaje cifrado o uno pegado en el chat.

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
MI_ID = 5841653022        # tu propio Chat ID
ID_DESTINO = 1431179602   # el Chat ID de tu compañero (rocko)

# --- Si eres PIERO, intercambia los numeros: ---
# MI_ID = 6191839605
# ID_DESTINO = 5841653022

# La clave secreta compartida del chat. Los dos DEBEN usar la misma.
# (Se deriva de una frase secreta acordada entre ambos.)
FRASE_SECRETA = "clave compartida del grupo SI"
CLAVE = hashlib.sha256(FRASE_SECRETA.encode()).digest()

# Ultimo payload cifrado visto (hex), para el comando "descifrar"
ultimo_cifrado_hex = None


# ============================================================
# FUNCIONES DE ENVIO Y RECEPCION
# ============================================================

def _normalizar_hex(texto):
    """Quita espacios y prefijo CIFRADO: si viene en el texto."""
    t = texto.strip()
    if t.upper().startswith("CIFRADO:"):
        t = t[8:].strip()
    return t.replace(" ", "")


def _hex_de_comando_descifrar(texto):
    """Extrae hex de 'descifrar' o 'descifrar <hex>'. None = usar el ultimo guardado."""
    resto = texto.strip()[len("descifrar") :].strip()
    if not resto:
        return None
    return _normalizar_hex(resto)


def descifrar_desde_hex(hexa):
    """Descifra bytes en hex. Devuelve (texto, None) o (None, mensaje de error)."""
    if not hexa:
        return None, "No hay datos cifrados."
    try:
        datos = bytes.fromhex(hexa)
    except ValueError:
        return None, "El texto no es hexadecimal valido."
    try:
        return descifrar(datos, CLAVE), None
    except Exception:
        return None, "No se pudo descifrar con la clave actual."


def _mostrar_descifrado(original, origen="Compañero"):
    print(f"\n[{origen} descifrado] {original}")
    print("[Tu] > ", end="", flush=True)


async def enviar(bot, texto):
    """Cifra el texto y lo envia al compañero por Telegram."""
    cifrado = cifrar(texto, CLAVE)
    # Convertimos los bytes cifrados a texto hexadecimal para enviarlos.
    # Le ponemos una etiqueta para distinguir mensajes cifrados de otros.
    mensaje = "CIFRADO:" + cifrado.hex()
    await bot.send_message(chat_id=ID_DESTINO, text=mensaje)


async def _responder_descifrado(bot, chat_id, original):
    """Confirma en Telegram que el descifrado se hizo (tambien sale en consola)."""
    await bot.send_message(
        chat_id=chat_id,
        text=f"[Descifrado] {original}",
    )


async def _procesar_texto_telegram(bot, chat_id, texto):
    """Maneja CIFRADO:, comando descifrar y hex suelto guardado para despues."""
    global ultimo_cifrado_hex
    texto_stripped = texto.strip()
    texto_lower = texto_stripped.lower()

    if texto_lower == "descifrar" or texto_lower.startswith("descifrar "):
        hexa = _hex_de_comando_descifrar(texto_stripped)
        if hexa is None:
            hexa = ultimo_cifrado_hex
        original, err = descifrar_desde_hex(hexa)
        if err:
            print(f"\n[!] {err}")
            print("[Tu] > ", end="", flush=True)
            await bot.send_message(chat_id=chat_id, text=f"[!] {err}")
            return
        _mostrar_descifrado(original)
        await _responder_descifrado(bot, chat_id, original)
        return

    if texto_stripped.upper().startswith("CIFRADO:"):
        hexa = _normalizar_hex(texto_stripped)
        ultimo_cifrado_hex = hexa
        original, err = descifrar_desde_hex(hexa)
        if err:
            print(f"\n[!] {err}")
            print("[Tu] > ", end="", flush=True)
            return
        _mostrar_descifrado(original)
        return

    # Hex cifrado sin prefijo: guardar y avisar que escriban "descifrar"
    posible = _normalizar_hex(texto_stripped)
    if len(posible) >= 16 and all(c in "0123456789abcdefABCDEF" for c in posible):
        ultimo_cifrado_hex = posible
        print("\n[*] Mensaje cifrado guardado. Escribe 'descifrar' en Telegram para verlo.")
        print("[Tu] > ", end="", flush=True)


async def escuchar(bot):
    """Revisa mensajes de Telegram (compañero o tu chat con el bot)."""
    global ultimo_cifrado_hex
    ultimo_update = 0
    chats_validos = {MI_ID, ID_DESTINO}
    while True:
        try:
            updates = await bot.get_updates(offset=ultimo_update + 1, timeout=10)
            for update in updates:
                ultimo_update = update.update_id
                if not update.message or not update.message.text:
                    continue
                chat_id = update.message.chat_id
                if chat_id not in chats_validos:
                    continue
                await _procesar_texto_telegram(bot, chat_id, update.message.text)
        except Exception:
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
    print("[*] En Telegram: 'descifrar' descifra el ultimo CIFRADO: recibido.")
    print("[*] Tambien: 'descifrar <hex>' o 'descifrar' en esta terminal.")
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
        texto_cmd = texto.strip().lower()
        if texto_cmd == "descifrar" or texto_cmd.startswith("descifrar "):
            hexa = _hex_de_comando_descifrar(texto.strip())
            if hexa is None:
                hexa = ultimo_cifrado_hex
            original, err = descifrar_desde_hex(hexa)
            if err:
                print(f"[!] {err}")
            else:
                print(f"[Descifrado] {original}")
            continue
        try:
            await enviar(bot, texto)
        except Exception as e:
            print(f"[!] Error al enviar: {e}")

    tarea_escuchar.cancel()
    print("[*] Chat cerrado.")


if __name__ == "__main__":
    asyncio.run(main())
