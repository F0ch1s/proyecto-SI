"""
============================================================
 SCRIPT DE AUDITORÍA CRIPTOGRÁFICA
 Evalúa empíricamente las propiedades de Feistel-X para 
 respaldar la sección de Discusión del artículo académico.
============================================================
Uso: python3 analisis_feistel.py
"""
 
import hashlib
import time
import math
from cifrado import cifrar, descifrar
 
# Generación de la clave maestra de prueba
CLAVE = hashlib.sha256(b"clave_prueba_SI_2025").digest()
 
print("=" * 60)
print("  ANÁLISIS DE FEISTEL-X — Mediciones empíricas")
print("=" * 60)
 
 
# ============================================================
# 1. PRUEBA DE CORRECTITUD (REVERSIBILIDAD)
# Valida que el proceso de descifrado recupere exactamente
# el texto plano original, sin pérdida de información.
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
# 2. EVALUACIÓN DEL EFECTO AVALANCHA
# Mide la dispersión de bits. Un cambio mínimo en la entrada
# (ej. 1 bit) debería alterar idealmente el 50% de la salida.
# ============================================================
print("\n[2] EFECTO AVALANCHA")
print("  (Mide el porcentaje de variación binaria ante cambios mínimos)")
 
def bits_diferentes(a, b):
    # Calcula la distancia de Hamming a nivel de bits entre dos secuencias
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))
 
# Vectores de prueba con variaciones mínimas (1 carácter o 1 bit)
pares = [
    ("Hola Rocko", "Hola Rockp"),   
    ("AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAB"),  
    ("Mensaje secreto", "Mensaje Secreto"),  
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
print(f"  (Referencia AES: ~50% | Ideal >= 50%)")
 
 
# ============================================================
# 3. CÁLCULO DE ENTROPÍA DE SHANNON
# Evalúa el grado de aleatoriedad del criptograma. 
# El límite teórico de un cifrado perfecto es de 8 bits/byte.
# ============================================================
print("\n[3] ENTROPÍA DE SHANNON DEL TEXTO CIFRADO")
print("  (Cuantifica la incertidumbre y dispersión estadística)")
 
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
 
# Se genera una carga útil repetitiva para estresar el algoritmo
texto_prueba = ("Este es un texto de prueba para medir la entropia. " * 50)
cifrado_prueba = cifrar(texto_prueba, CLAVE)
 
ent_original = calcular_entropia(texto_prueba.encode())
ent_cifrado = calcular_entropia(cifrado_prueba)
print(f"  Texto original:  {ent_original:.2f} bits/byte")
print(f"  Texto cifrado:   {ent_cifrado:.2f} bits/byte")
print(f"  Ideal teórico:   8.00 bits/byte")
 
 
# ============================================================
# 4. RENDIMIENTO COMPUTACIONAL (TIEMPO Y THROUGHPUT)
# Realiza pruebas de estrés para medir la latencia de
# ejecución y la tasa de transferencia de datos (Mbps).
# ============================================================
print("\n[4] RENDIMIENTO Y TASA DE TRANSFERENCIA (THROUGHPUT)")
 
# Benchmark con carga de 1 KB iterada 100 veces
texto_1kb = "A" * 1024
inicio = time.perf_counter()
for _ in range(100):  
    cifrar(texto_1kb, CLAVE)
fin = time.perf_counter()
tiempo_promedio_ms = ((fin - inicio) / 100) * 1000
throughput_mbps = (1024 * 8) / (tiempo_promedio_ms / 1000) / 1_000_000
 
print(f"  Tiempo promedio cifrado (1KB): {tiempo_promedio_ms:.2f} ms")
print(f"  Throughput estimado: {throughput_mbps:.2f} Mbps")
 
# Simulación de latencia en escenario telemático real
texto_chat = "Hola, como estas? Este es un mensaje tipico de chat."
inicio = time.perf_counter()
for _ in range(1000):
    cifrar(texto_chat, CLAVE)
fin = time.perf_counter()
tiempo_chat_ms = ((fin - inicio) / 1000) * 1000
print(f"  Latencia por mensaje telemático (~50 bytes): {tiempo_chat_ms:.3f} ms")
 
 
# ============================================================
# 5. ANÁLISIS DE VULNERABILIDAD ESTRUCTURAL (MODO ECB)
# Demuestra que cifrar bloques de forma independiente genera
# patrones repetitivos si el texto contiene secuencias idénticas.
# ============================================================
print("\n[5] DEMOSTRACIÓN DE VULNERABILIDAD (MODO ECB)")
print("  (Bloques planos idénticos producen cifrados idénticos)")
 
# Inyección de patrón repetitivo (3 bloques de 4 bytes)
m_repetido = "HOLAHOLAHOLA"  
c_repetido = cifrar(m_repetido, CLAVE)
print(f"  Mensaje: '{m_repetido}' ({len(m_repetido)} bytes)")
print(f"  Cifrado (hex): {c_repetido.hex()}")

# Segmentación para análisis visual de bloques
bloques = [c_repetido[i:i+8].hex() for i in range(0, len(c_repetido), 8)]
for i, b in enumerate(bloques):
    print(f"    Bloque {i}: {b}")
    
# Verificación de colisiones
if len(set(bloques)) < len(bloques):
    print("  ALERTA: Se detectaron bloques cifrados idénticos (Patrón ECB confirmado)")
else:
    print("  Bloques heterogéneos detectados.")
 
 
# ============================================================
# RESUMEN FINAL DE MÉTRICAS
# ============================================================
print("\n" + "=" * 60)
print("  MÉTRICAS CONSOLIDADAS PARA LA TABLA DE RESULTADOS")
print("=" * 60)
print(f"  Efecto Avalancha Promedio : {promedio:.1f}%")
print(f"  Entropía del Criptograma  : {ent_cifrado:.2f} bits/byte")
print(f"  Latencia de Transmisión   : {tiempo_chat_ms:.3f} ms")
print(f"  Throughput Computacional  : {throughput_mbps:.2f} Mbps")
print(f"  Test de Correctitud       : {'100% Exitoso' if todos_ok else 'Fallido'}")
print("=" * 60)