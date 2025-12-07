# PCAPCES - Analizador de tráfico de red para detección de cosas

## ¿Qué hace este programa?

Este programa analiza archivos de captura de tráfico de red (archivos `.pcap`) para **detectar actividad de malagente** en un equipo. Es como un "detective digital" que examina las comunicaciones de red en busca de señales de que un equipo ha sido infectada por bichería.

---

## ¿Qué información puede detectar?

El programa busca y te muestra:

| Información | Descripción |
|-------------|-------------|
| 🖥️ **Equipo infectado** | Identifica qué equipo está comprometido (dirección IP, nombre del equipo) |
| 👤 **Usuario afectado** | Detecta el nombre de usuario de la cuenta comprometida |
| 🌐 **Sitios web maliciosos** | Encuentra dominios falsos que imitan páginas legítimas (ej: páginas falsas de Google) |
| 📡 **Servidores de control** | Detecta comunicaciones con servidores que controlan el malware |
| 🦠 **Tipo de malware** | Clasifica el tipo de amenaza detectada |
| 📥 **Archivos descargados** | Identifica archivos sospechosos descargados |
| 🔑 **Credenciales expuestas** | Detecta si se enviaron contraseñas o datos sensibles |

---

## 📋 Requisitos previos

Antes de usar el programa, necesitas tener instalado:

1. **Python 3** - El lenguaje en el que está escrito el programa
2. **Wireshark/tshark** - Herramienta para leer archivos de red

Estas dependencias están definidas en el archivo requirements.txt
---

## Cómo usar el programa?

### Paso 1: Preparar el entorno

La forma más rápida de ejecutar el programa, será abrir una terminal (Ctrl+Alt+T) y ejecutar en ella:

./ejecutar.sh

Si el script no tiene permisos se le pueden dar con chmod +x. Este script debería crear el entorno virtual, activarlo e instalar las dependencias de requirements.txt en el archivo virtual. Después ejecutará en análisis configurado.

La opción menos rápida para ejecutar el programa será: abrir una terminal y ejecuta estos comandos uno por uno:

```bash
# Crear un entorno virtual (espacio aislado para el programa)
python3 -m venv .venv

# Activar el entorno virtual
source .venv/bin/activate

# Instalar las herramientas necesarias
pip install -r requirements.txt
```

### Paso 2: Configurar el archivo a analizar

1. Coloca tu archivo `.pcap` en la carpeta del programa
2. Abre el archivo `config.py` con un editor de texto
3. Cambia el nombre del archivo en la línea `ARCHIVO_PCAP`:

```python
ARCHIVO_PCAP = "nombre_de_tu_archivo.pcap"
```

### Paso 3: Ejecutar el análisis

```bash
python main.py
```

### Paso 4: Ver los resultados

El programa mostrará un reporte en pantalla con colores que indica:

- ✅ Información encontrada (en verde/amarillo)
- ⚠️ Actividad sospechosa detectada
- 🔴 Amenazas identificadas

---

## 📊 Entendiendo los resultados

El reporte se divide en secciones:

1. **Cliente infectado**: Datos del equipo comprometido
2. **Clasificación del malware**: Tipo de amenaza y técnicas utilizadas
3. **Resumen de amenazas**: Lista de todos los elementos peligrosos encontrados

---

## ❓ Preguntas frecuentes

### ¿Qué es un archivo PCAP?

Es un archivo que contiene una grabación del tráfico de red. Es como una "grabación de video" pero de las comunicaciones entre equipos.

### ¿De dónde obtengo un archivo PCAP?

Puedes crearlo con programas como **Wireshark** que capturan el tráfico de red, o pueden proporcionártelo para análisis forense.

### ¿Es seguro analizar archivos PCAP?

Sí, el programa solo **lee** el archivo, no ejecuta nada malicioso. Es seguro usarlo para análisis.

---

## Al terminar de usar el programa

Cuando termines de usar el programa, desactiva el entorno virtual:

```bash
deactivate
```

---

## 👨‍💻 Créditos

Creado por **entreunosyceros** para el curso de seguridad informática
