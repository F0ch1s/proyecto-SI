"""
============================================================
  CIFRADO FEISTEL-X 
============================================================
Implementación de un cifrado por bloques (8 bytes) usando 
una red de Feistel de 4 rondas.

Funciones a exportar para el equipo:
  - cifrar(texto, clave) -> devuelve bytes cifrados
  - descifrar(datos, clave) -> devuelve el texto original
"""
import hashlib
# ============================================================
# 1. S-BOX
# ============================================================
# Tabla de sustitución (usamos la misma de AES). 
# Rompe patrones obvios entre el mensaje y el cifrado (confusión).
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
# ============================================================
# 2. FUNCIONES INTERNAS
# ============================================================

def _rotar_izquierda(byte, n):
    """Desplaza los bits a la izquierda de forma circular."""
    return ((byte << n) | (byte >> (8 - n))) & 0xFF


def _rotar_derecha(byte, n):
    """Desplaza los bits a la derecha (se usa para descifrar)."""
    return ((byte >> n) | (byte << (8 - n))) & 0xFF

def _permutar(bloque):
    """Desordena los bits del bloque para esparcir la información (difusión)."""
    return bytes(_rotar_izquierda(b, (i % 7) + 1) for i, b in enumerate(bloque))

def _derivar_subclaves(clave_maestra, rondas=4):
    """Genera una subclave distinta por ronda usando SHA-256."""
    subclaves = []
    for r in range(rondas):
        h = hashlib.sha256(clave_maestra + bytes([r])).digest()
        subclaves.append(h[:4])  # Tomamos solo 4 bytes por ronda
    return subclaves

def _funcion_F(medio, subclave):
    """
    Núcleo del cifrado. Transforma 4 bytes en 3 pasos:
      1. Sustituye (S-Box)
      2. Permuta (bits)
      3. Mezcla con la subclave (XOR)
    """
    sustituido = bytes(SBOX[b] for b in medio)
    permutado = _permutar(sustituido)
    mezclado = bytes(permutado[i] ^ subclave[i] for i in range(4))
    return mezclado
# ============================================================
# 3. CIFRADO / DESCIFRADO (Bloques de 8 bytes)
# ============================================================
def _cifrar_bloque(bloque, clave):
    """Pasa un bloque de 8 bytes por las 4 rondas de Feistel."""
    subclaves = _derivar_subclaves(clave)
    L, R = bloque[:4], bloque[4:]
    
    for r in range(4):
        nueva_R = bytes(L[i] ^ _funcion_F(R, subclaves[r])[i] for i in range(4))
        L, R = R, nueva_R
        
    return L + R
def _descifrar_bloque(bloque, clave):
    """Hace el proceso inverso aplicando las subclaves al revés."""
    subclaves = _derivar_subclaves(clave)
    L, R = bloque[:4], bloque[4:]
    
    for r in reversed(range(4)):
        R_anterior = L
        L_anterior = bytes(R[i] ^ _funcion_F(R_anterior, subclaves[r])[i] for i in range(4))
        L, R = L_anterior, R_anterior
        
    return L + R
# ============================================================
# 4. PADDING (PKCS#7)
# ============================================================
# Rellena los datos para asegurar que el tamaño final sea múltiplo de 8.

def _agregar_padding(datos):
    falta = 8 - (len(datos) % 8)
    return datos + bytes([falta] * falta)
def _quitar_padding(datos):
    falta = datos[-1]
    return datos[:-falta]
# ============================================================
# 5. API DEL MÓDULO
# ============================================================
def cifrar(texto, clave):
    """Convierte un string a bytes cifrados."""
    datos = _agregar_padding(texto.encode("utf-8"))
    resultado = b""
    
    # Procesa de 8 en 8 bytes
    for i in range(0, len(datos), 8):
        resultado += _cifrar_bloque(datos[i:i+8], clave)
        
    return resultado

def descifrar(datos, clave):
    """Recupera el string original a partir de los bytes cifrados."""
    resultado = b""
    
    for i in range(0, len(datos), 8):
        resultado += _descifrar_bloque(datos[i:i+8], clave)
        
    return _quitar_padding(resultado).decode("utf-8")
# ============================================================
# 6. TESTS RÁPIDOS
# ============================================================
if __name__ == "__main__":
    print("Corriendo pruebas de cifrado...")
    
    # Usamos el hash de un string como clave (32 bytes)
    clave = hashlib.sha256(b"super_secreto").digest()
   
    mensajes_prueba = [
        "Hola equipo!",
        "Seguridad Informatica 2025",
        "Mensaje con padding raro"
    ]
    
    for m in mensajes_prueba:
        cifrado = cifrar(m, clave)
        descifrado = descifrar(cifrado, clave)
        assert descifrado == m, f"Fallo al descifrar: {m}"
        
    print("[OK] Todas las pruebas pasaron.")  
