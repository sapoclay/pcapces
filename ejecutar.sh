#!/bin/bash
# Script para ejecutar el analizador PCAP
# Activa automáticamente el entorno virtual, instala dependencias y ejecuta el análisis

# Nombre del entorno virtual
VENV_DIR=".venv"

# Verificar si existe el entorno virtual, si no, crearlo
if [ ! -d "$VENV_DIR" ]; then
    echo "Creando entorno virtual en $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

# Activar el entorno virtual
source "$VENV_DIR/bin/activate"

# Instalar dependencias si existe requirements.txt
if [ -f "requirements.txt" ]; then
    echo "Verificando/Instalando dependencias..."
    pip install -r requirements.txt -q
fi

# Ejecutar el script principal
echo "Iniciando pcapCES..."
python3 main.py

# Desactivar al finalizar
deactivate
