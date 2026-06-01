"""
============================================================
  SCRIPT DE ANALISIS 
  Mide las propiedades criptograficas de Feistel-X
  para la seccion de Resultados y Discusion del paper.
============================================================
Ejecutar con: python3 analisis_feistel.py
"""
 
import hashlib
import time
import math
from cifrado import cifrar, descifrar
 
# Clave de prueba
CLAVE = hashlib.sha256(b"clave_prueba_SI_2025").digest()
 
print("=" * 60)
print("  ANALISIS DE FEISTEL-X — Mediciones para el paper")
print("=" * 60)
 
 
# ============================================================
# 1. CORRECTITUD
# ============================================================
print("\n[1] CORRECTITUD")
mensajes_prueba = [
    "Hola mundo",
    "Mensaje de prueba 123",
    "Seguridad Informatica UCSM",
]
todos_ok = True
for m in mensajes_prueba:
    c = cifrar(m, CLAVE)
    d = descifrar(c, CLAVE)
    ok = (d == m)
    print(f"  '{m}' -> cifrado -> descifrado -> '{d}' : {'OK' if ok else 'ERROR'}")
    if not ok:
        todos_ok = False
print(f"  Resultado: {'TODOS CORRECTOS' if todos_ok else 'HAY ERRORES'}")
 
 
# ============================================================
# 2. EFECTO AVALANCHA
# ============================================================
print("\n[2] EFECTO AVALANCHA")
print("  (cuantos bits cambian en el cifrado si cambio 1 bit del mensaje)")
 
def bits_diferentes(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
 
# Prueba con varios pares de mensajes similares
pares = [
    ("Hola Rocko", "Hola Rockp"),   # ultimo caracter distinto
    ("AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAB"),  # 1 caracter distinto
    ("Mensaje secreto", "Mensaje Secreto"),  # M mayuscula
]
 
avalanchas = []
for m1, m2 in pares:
    c1 = cifrar(m1, CLAVE)
    c2 = cifrar(m2, CLAVE)
    n = min(len(c1), len(c2)) * 8
    d = bits_diferentes(c1, c2)
    pct = 100 * d / n
    avalanchas.append(pct)
    print(f"  '{m1}' vs '{m2}'")
    print(f"  Bits diferentes: {d}/{n} = {pct:.1f}%")
 
promedio = sum(avalanchas) / len(avalanchas)
print(f"\n  PROMEDIO EFECTO AVALANCHA: {promedio:.1f}%")
print(f"  (AES referencia: ~50% | ideal >= 50%)")
 
 
# ============================================================
# 3. ENTROPIA DEL TEXTO CIFRADO
# ============================================================
print("\n[3] ENTROPIA DEL TEXTO CIFRADO")
print("  (mide que tan 'aleatorio' parece el cifrado)")
print("  (ideal = 8 bits/byte, texto plano tipico ~4-5 bits/byte)")
 
def calcular_entropia(data):
    if not data:
        return 0
    frec = {}
    for byte in data:
        frec[byte] = frec.get(byte, 0) + 1
    ent = 0
    for f in frec.values():
        p = f / len(data)
        ent -= p * math.log2(p)
    return ent
 
texto_prueba = ("Este es un texto de prueba para medir la entropia. " * 50)
cifrado_prueba = cifrar(texto_prueba, CLAVE)
 
ent_original = calcular_entropia(texto_prueba.encode())
ent_cifrado = calcular_entropia(cifrado_prueba)
print(f"  Texto original:  {ent_original:.2f} bits/byte")
print(f"  Texto cifrado:   {ent_cifrado:.2f} bits/byte")
print(f"  Ideal teorico:   8.00 bits/byte")
 
 
# ============================================================
# 4. TIEMPO Y THROUGHPUT
# ============================================================
print("\n[4] TIEMPO DE CIFRADO Y THROUGHPUT")
 
# Medir con mensaje de 1 KB
texto_1kb = "A" * 1024
inicio = time.perf_counter()
for _ in range(100):  # 100 repeticiones para mayor precision
    cifrar(texto_1kb, CLAVE)
fin = time.perf_counter()
tiempo_promedio_ms = ((fin - inicio) / 100) * 1000
throughput_mbps = (1024 * 8) / (tiempo_promedio_ms / 1000) / 1_000_000
 
print(f"  Tiempo promedio cifrar 1KB: {tiempo_promedio_ms:.2f} ms")
print(f"  Throughput: {throughput_mbps:.2f} Mbps")
 
# Comparacion: tiempo para un mensaje de chat tipico (50 bytes)
texto_chat = "Hola, como estas? Este es un mensaje tipico de chat."
inicio = time.perf_counter()
for _ in range(1000):
    cifrar(texto_chat, CLAVE)
fin = time.perf_counter()
tiempo_chat_ms = ((fin - inicio) / 1000) * 1000
print(f"  Tiempo cifrar mensaje de chat (~50 bytes): {tiempo_chat_ms:.3f} ms")
print(f"  (latencia imperceptible para el usuario)")
 
 
# ============================================================
# 5. DEMOSTRACION DEBILIDAD ECB
# ============================================================
print("\n[5] DEMOSTRACION DEBILIDAD MODO ECB")
print("  (bloques identicos producen cifrados identicos)")
 
m_repetido = "HOLAHOLAHOLA"  # "HOLA" repetido 3 veces — 3 bloques de 4 bytes
# con padding: 3 bloques de 8 bytes donde primer mitad = HOLA
c_repetido = cifrar(m_repetido, CLAVE)
print(f"  Mensaje: '{m_repetido}' ({len(m_repetido)} bytes)")
print(f"  Cifrado (hex): {c_repetido.hex()}")
# Mostrar bloques
bloques = [c_repetido[i:i+8].hex() for i in range(0, len(c_repetido), 8)]
for i, b in enumerate(bloques):
    print(f"    Bloque {i}: {b}")
# Verificar si hay bloques iguales
if len(set(bloques)) < len(bloques):
    print("  ATENCION: hay bloques cifrados IGUALES -> debilidad ECB demostrada")
else:
    print("  Los bloques son diferentes (el mensaje no era suficientemente repetitivo)")
 
 
# ============================================================
# RESUMEN FINAL
# ============================================================
print("\n" + "=" * 60)
print("  RESUMEN PARA EL PAPER")
print("=" * 60)
print(f"  Efecto avalancha promedio : {promedio:.1f}%")
print(f"  Entropia texto cifrado    : {ent_cifrado:.2f} bits/byte")
print(f"  Tiempo cifrar mensaje chat: {tiempo_chat_ms:.3f} ms")
print(f"  Throughput (1KB)          : {throughput_mbps:.2f} Mbps")
print(f"  Correctitud               : {'100%' if todos_ok else 'ERROR'}")
print("=" * 60)