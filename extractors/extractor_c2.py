"""
EXTRACTOR DE SERVIDORES C2 (Command & Control)
===============================================

Este módulo detecta servidores de comando y control analizando
conexiones HTTP a direcciones IP directas (sin nombre de dominio).
"""

import re
import config


class ExtractorC2:
    """
    Detecta servidores C2 en el tráfico HTTP.
    """
    
    def __init__(self):
        """Inicializa el extractor con un diccionario de IPs C2."""
        # Diccionario: ip -> número de paquete
        self.ips_c2 = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete HTTP para detectar conexiones a servidores C2.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # Los servidores C2 son los equipos que controlan el malware
            # Conexiones HTTP a IPs directas (sin nombre de dominio) son muy sospechosas
            if hasattr(pkt, 'http'):
                todos_campos = pkt.http._all_fields
                
                # Detectar conexiones HTTP a IPs directas (indicador de C2)
                # Visitar una IP directamente es sospechoso
                if 'http.host' in todos_campos:
                    host = str(todos_campos['http.host'])
                    
                    # Verificar si el host es una dirección IP (formato: 1.2.3.4)
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
                        # Excluir IPs privadas (red local) y multicast
                        # Solo nos interesan IPs públicas (Internet)
                        if not host.startswith(config.PREFIJOS_C2_EXCLUIDOS):
                            if host not in self.ips_c2:
                                self.ips_c2[host] = getattr(pkt, 'number', 'N/A')
        except:
            pass
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con la lista de IPs de servidores C2 (objetos con ip y paquete)
        """
        # Convertir a lista de diccionarios para el reporteador
        lista_c2 = [
            {'ip': ip, 'paquete': paquete}
            for ip, paquete in self.ips_c2.items()
        ]
        
        return {
            'ips_c2': lista_c2
        }
