"""
ANALIZADOR DE MALWARE PCAP - PUNTO DE ENTRADA PRINCIPAL DEL PROGRAMA
====================================================================

Este script analiza archivos .pcap para identificar:
- Equipos infectados con malware
- Dominios maliciosos (páginas falsas)
- Servidores de comando y control (C2)
- Tipo de malware y técnicas utilizadas

B======================================================>


"""

import os
import sys
from colorama import init, Fore, Style
import config
from analizador import AnalizadorPcap
from clasificador import ClasificadorMalware
from reporteador import Reporteador

# Inicializar colorama para que funcione en todos los sistemas
init(autoreset=True)

def imprimir_banner():
    banner = fr"""
{Fore.CYAN}
  _ __   ___ __ _ _ __   ____ _____ ____  
 | '_ \ / __/ _` | '_ \ / ___| ____/ ___| 
 | |_) | (_| (_| | |_) | |___|  _| \___ \ 
 | .__/ \___\__,_| .__/ \____|_____|____/ 
 |_|             |_|                      
{Style.RESET_ALL}
    """
    print(banner)
    print(f"{Style.DIM}Creado por entreunosyceros{Style.RESET_ALL}\n")


def main():
    """
    Función principal que coordina el análisis completo.
    """
    imprimir_banner()
    
    # Archivo PCAP a analizar (configurado en config.py)
    archivo_pcap = config.ARCHIVO_PCAP
    
    # Verificar que el archivo PCAP existe antes de continuar
    if not os.path.exists(archivo_pcap):
        print(f"{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.RED}  ❌ ERROR: No se encontró el archivo de captura{Style.RESET_ALL}")
        print(f"{Fore.RED}{'=' * 60}{Style.RESET_ALL}")
        print()
        print(f"  El archivo {Fore.YELLOW}'{archivo_pcap}'{Style.RESET_ALL} no existe.")
        print()
        print(f"  {Fore.CYAN}¿Qué puedes hacer?{Style.RESET_ALL}")
        print(f"  1. Asegúrate de que el archivo .pcap esté en la carpeta del programa")
        print(f"  2. Verifica que el nombre del archivo sea correcto")
        print(f"  3. Edita el archivo {Fore.YELLOW}'config.py'{Style.RESET_ALL} y cambia el valor de")
        print(f"     {Fore.GREEN}ARCHIVO_PCAP{Style.RESET_ALL} por el nombre correcto de tu archivo")
        print()
        print(f"  {Fore.CYAN}Ejemplo en config.py:{Style.RESET_ALL}")
        print(f"     ARCHIVO_PCAP = \"mi_captura.pcap\"")
        print()
        sys.exit(1)
    
    # Paso 1: Analizar el archivo PCAP
    analizador = AnalizadorPcap(archivo_pcap)
    resultados_analisis = analizador.analizar()
    
    # Paso 2: Clasificar el malware
    clasificador = ClasificadorMalware()
    clasificacion = clasificador.clasificar(resultados_analisis)
    
    # Paso 3: Generar el reporte completo
    reporteador = Reporteador()
    reporteador.generar_reporte_completo(resultados_analisis, clasificacion)


if __name__ == "__main__":
    main()
