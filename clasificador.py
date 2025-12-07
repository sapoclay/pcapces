"""
CLASIFICADOR DE MALWARE
========================

Este módulo clasifica el tipo de malware basándose en los
indicadores de compromiso (IOCs) encontrados en el análisis.
"""

import config


class ClasificadorMalware:
    """
    Clasifica el malware basándose en IOCs y patrones de comportamiento.
    """
    
    def __init__(self):
        """Inicializa el clasificador."""
        pass
    
    def clasificar(self, resultados_analisis):
        """
        Clasifica el malware basándose en los resultados del análisis.
        
        Args:
            resultados_analisis: Diccionario con los resultados del análisis PCAP
        
        Devuelve:
            dict: Diccionario con la clasificación del malware
        """
        # Valores por defecto
        tipo_malware = "Desconocido"
        familia_malware = "Desconocido"
        cves = []
        cwes = []
        tecnicas_ataque = []
        
        # Analizar patrones de comportamiento
        tiene_dominio_auth_falso = len(resultados_analisis.get('dominios_auth_falsos', [])) > 0
        tiene_conexion_c2 = len(resultados_analisis.get('ips_c2', [])) > 0
        
        # Clasificación basada en IOCs (indicadores de compromiso)
        if tiene_dominio_auth_falso:
            tipo_malware = config.TIPO_MALWARE_AUTH_FALSA
            familia_malware = config.FAMILIA_MALWARE_AUTH_FALSA
            
            # CWEs relacionados con phishing y robo de credenciales
            cwes = config.CWES_ROBO_CREDENCIALES.copy()
            
            # MITRE ATT&CK Techniques
            tecnicas_ataque = config.TECNICAS_MITRE_ATTACK.copy()
            
            # CVEs potenciales (basado en el tipo de ataque)
            cves = config.CVES_VECTORES_INFECCION_COMUNES.copy()
        
        return {
            'tipo': tipo_malware,
            'familia': familia_malware,
            'cves': cves,
            'cwes': cwes,
            'mitre_attack': tecnicas_ataque
        }
