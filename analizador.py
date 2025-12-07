"""
ANALIZADOR PRINCIPAL DE PCAP
=============================

Este módulo orquesta el análisis completo de un archivo PCAP,
delegando a extractores especializados y consolidando resultados.
"""

import pyshark
from colorama import Fore, Style
import config
from extractors import (
    ExtractorIP,
    ExtractorHostname,
    ExtractorUsuario,
    ExtractorDNS,
    ExtractorC2,
    ExtractorSO,
    ExtractorPuertosSospechosos,
    ExtractorEscaneoPuertos,
    ExtractorDescargas,
    ExtractorTransferencias,
    ExtractorCredenciales,
    ExtractorUserAgents,
    ExtractorARP,
    ExtractorRTT,
    ExtractorErrores
)


class AnalizadorPcap:
    """
    Orquesta principal que coordina todos los extractores
    para analizar un archivo PCAP.
    """
    
    def __init__(self, archivo_pcap):
        """
        Inicializa el analizador con la ruta al archivo PCAP.
        
        Args:
            archivo_pcap: Ruta al archivo PCAP a analizar
        """
        self.archivo_pcap = archivo_pcap
        
        # Inicializar todos los extractores
        self.extractor_ip = ExtractorIP()
        self.extractor_hostname = ExtractorHostname()
        self.extractor_usuario = ExtractorUsuario()
        self.extractor_dns = ExtractorDNS()
        self.extractor_c2 = ExtractorC2()
        self.extractor_so = ExtractorSO()
        self.extractor_puertos_sospechosos = ExtractorPuertosSospechosos()
        self.extractor_escaneo_puertos = ExtractorEscaneoPuertos()
        self.extractor_descargas = ExtractorDescargas()
        self.extractor_transferencias = ExtractorTransferencias()
        self.extractor_credenciales = ExtractorCredenciales()
        self.extractor_user_agents = ExtractorUserAgents()
        self.extractor_arp = ExtractorARP()
        self.extractor_rtt = ExtractorRTT()
        self.extractor_errores = ExtractorErrores()
    
    def analizar(self):
        """
        Ejecuta el análisis completo del archivo PCAP.
        
        Deveulve:
            dict: Diccionario con todos los resultados del análisis
        """
        print("=" * 80)
        print(f"{Fore.CYAN}[INFO] Analizando el archivo pcap...{Style.RESET_ALL}")
        
        # Abrir el archivo PCAP para lectura
        cap = pyshark.FileCapture(
            self.archivo_pcap,
            use_json=config.CONFIG_PCAP['use_json'],
            keep_packets=config.CONFIG_PCAP['keep_packets']
        )
        
        # Recorrer todos los paquetes y delegar a cada extractor
        for pkt in cap:
            # Procesar con cada extractor de forma aislada
            try:
                self.extractor_ip.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_hostname.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_usuario.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_dns.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_c2.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_so.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_puertos_sospechosos.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_escaneo_puertos.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_descargas.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_transferencias.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_credenciales.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_user_agents.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_arp.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_rtt.procesar_paquete(pkt)
            except: pass
            
            try:
                self.extractor_errores.procesar_paquete(pkt)
            except: pass
        
        cap.close()
        
        # Consolidar resultados de todos los extractores
        resultados = self._consolidar_resultados()
        
        # Mostrar resumen del análisis
        self._imprimir_resumen(resultados)
        
        return resultados
    
    def _consolidar_resultados(self):
        """
        Consolida los resultados de todos los extractores.
        
        Devuelve:
            dict: Diccionario con todos los resultados consolidados
        """
        resultados = {}
        
        # Obtener resultados de cada extractor
        resultados.update(self.extractor_ip.obtener_resultados())
        resultados.update(self.extractor_hostname.obtener_resultados())
        resultados.update(self.extractor_usuario.obtener_resultados())
        resultados.update(self.extractor_dns.obtener_resultados())
        resultados.update(self.extractor_c2.obtener_resultados())
        resultados.update(self.extractor_so.obtener_resultados())
        resultados.update(self.extractor_puertos_sospechosos.obtener_resultados())
        resultados.update(self.extractor_escaneo_puertos.obtener_resultados())
        resultados.update(self.extractor_descargas.obtener_resultados())
        resultados.update(self.extractor_transferencias.obtener_resultados())
        resultados.update(self.extractor_credenciales.obtener_resultados())
        resultados.update(self.extractor_user_agents.obtener_resultados())
        resultados.update(self.extractor_arp.obtener_resultados())
        resultados.update(self.extractor_rtt.obtener_resultados())
        resultados.update(self.extractor_errores.obtener_resultados())
        
        return resultados
    
    def _imprimir_resumen(self, resultados):
        """
        Imprime un resumen del análisis realizado.
        
        Args:
            resultados: Diccionario con los resultados del análisis
        """
        print()
        print("=" * 80)
        print(f"{Fore.GREEN}[INFO] Análisis completado.{Style.RESET_ALL}")
        print()
        print("=" * 80)
        
        print(f"{Fore.CYAN}[INFO] IP infectada: {Fore.YELLOW}{resultados.get('ip_infectada', 'No encontrada')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Hostnames encontrados: {Fore.YELLOW}{len(resultados.get('hostnames', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Usuarios encontrados: {Fore.YELLOW}{len(resultados.get('usuarios', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Dominios sospechosos: {Fore.YELLOW}{len(resultados.get('dominios_auth_falsos', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Servidores C2 detectados: {Fore.YELLOW}{len(resultados.get('ips_c2', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Conexiones a puertos sospechosos: {Fore.YELLOW}{len(resultados.get('conexiones_puertos_sospechosos', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Escaneos de puertos detectados: {Fore.YELLOW}{len(resultados.get('escaneos_puertos', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Descargas sospechosas: {Fore.YELLOW}{len(resultados.get('descargas_sospechosas', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Transferencias grandes: {Fore.YELLOW}{len(resultados.get('transferencias_grandes', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Credenciales expuestas: {Fore.YELLOW}{len(resultados.get('credenciales_expuestas', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] User-Agents anómalos: {Fore.YELLOW}{len(resultados.get('user_agents_anomalos', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Anomalías ARP: {Fore.YELLOW}{len(resultados.get('anomalias_arp', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Conexiones lentas (RTT): {Fore.YELLOW}{len(resultados.get('conexiones_lentas', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Errores HTTP: {Fore.YELLOW}{len(resultados.get('errores_http', []))}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] CPEs generados: {Fore.YELLOW}{len(resultados.get('cpes', []))}{Style.RESET_ALL}")
        print()
