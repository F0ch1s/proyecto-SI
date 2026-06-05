# 🔐 Feistel-X — Chat Cifrado

Algoritmo de cifrado propio basado en red de Feistel aplicado a comunicaciones telemáticas.  
---

## ⚙️ Requisitos

- **Python 3.7 o superior**
- Solo para Telegram: instalar una librería extra

Verifica tu Python:
```bash
python3 --version
```

---

## 📁 Archivos del repositorio

| Archivo | Qué hace |
|---------|----------|
| `cifrado.py` | El algoritmo Feistel-X — cifrar y descifrar |
| `servidor.py` | Servidor del chat cifrado por TCP |
| `cliente.py` | Cliente del chat cifrado por TCP |
| `espia.py` | Interceptor que muestra el tráfico cifrado |
| `cliente_espia.py` | Cliente que conecta a través del espía |
| `chat_telegram.py` | Chat cifrado sobre Telegram |

> ⚠️ Todos los archivos deben estar en la **misma carpeta**.

---

## ▶️ Ejecución

### 1. Probar el algoritmo de cifrado

```bash
python3 cifrado.py
```

Resultado esperado:
```
Original   : Hola equipo!
Cifrado    : 4d3ee0be2ac0efba...
Descifrado : Hola equipo!
[OK] Todo cifrado y descifrado correctamente.
```

---

### 2. Chat cliente/servidor cifrado

Requiere **dos terminales** abiertas en la misma carpeta.

**Terminal 1 — Servidor:**
```bash
python3 servidor.py
```
Espera: `[*] Esperando que el cliente se conecte...`

**Terminal 2 — Cliente:**
```bash
python3 cliente.py
```

Cuando los dos estén corriendo escribe mensajes y presiona Enter.  
Escribe `salir` para terminar.

---

### 3. Demostración del espía (tráfico cifrado)

Requiere **tres terminales** abiertas en la misma carpeta.

**Terminal 1 — Servidor:**
```bash
python3 servidor.py
```

**Terminal 2 — Espía:**
```bash
python3 espia.py
```

**Terminal 3 — Cliente (pasa por el espía):**
```bash
python3 cliente_espia.py
```

Escribe un mensaje en el cliente. En la terminal del espía verás:
```
PAQUETE #1  interceptado  (CLIENTE -> SERVIDOR)
Bytes que viajan por la red: a3 f8 b2 c1 7d 4e ...
Como texto: [ILEGIBLE - los datos están cifrados]
```

---

### 4. Chat cifrado sobre Telegram

**Paso 1 — Instalar la librería:**
```bash
pip3 install python-telegram-bot
```

**Paso 2 — Configurar IDs en `chat_telegram.py`:**

Abre el archivo y edita la sección `CONFIGURACION`:

```python
# Si eres RODRIGO:
MI_ID      = 5841653022
ID_DESTINO = 6191839605   # ID de tu compañero

# Si eres PIERO, intercambia los números:
# MI_ID      = 6191839605
# ID_DESTINO = 5841653022
```

> Para saber tu Chat ID: abre tu bot en Telegram, manda cualquier mensaje,
> luego abre en el navegador:
> `https://api.telegram.org/botTU_TOKEN/getUpdates`
> y busca `"chat":{"id":XXXXXXXXX}`

**Paso 3 — Ejecutar en cada PC al mismo tiempo:**
```bash
python3 chat_telegram.py
```

Escribe mensajes en la terminal. En el chat del bot de Telegram verás:
```
CIFRADO:652adc299a7f012d...
```
Telegram nunca ve el texto real — solo los bytes cifrados.

Escribe `salir` para terminar.

---

## 🔑 Nota sobre la clave compartida

El chat de Telegram usa una frase secreta fija en el código:
```python
FRASE_SECRETA = "clave compartida del grupo SI"
```
Ambas personas deben tener **exactamente la misma frase** para que el descifrado funcione. No la cambies a menos que la cambies en los dos archivos a la vez.

---

