"""
EXTRACTOR DE DOMINIOS DNS MALICIOSOS
=====================================

Este módulo analiza consultas DNS para detectar dominios sospechosos
que podrían ser utilizados para phishing o robo de credenciales.
"""

import config


class ExtractorDNS:
    """
    Detecta dominios maliciosos en consultas DNS.
    """
    
    def __init__(self):
        """Inicializa el extractor con un diccionario de dominios sospechosos."""
        # Diccionario: dominio -> número de paquete
        self.dominios_sospechosos = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete DNS para detectar dominios maliciosos.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # DNS = Sistema de Nombres de Dominio. Traduce nombres a IPs
            if hasattr(pkt, 'dns'):
                todos_campos = pkt.dns._all_fields
                
                # Buscar en las consultas DNS (qué dominios se están visitando)
                if 'Queries' in todos_campos:
                    for clave, valor in todos_campos['Queries'].items():
                        if isinstance(valor, dict) and 'dns.qry.name' in valor:
                            dominio = str(valor['dns.qry.name']).lower()
                            
                            # Verificar si el dominio es sospechoso
                            es_sospechoso = any(
                                patron in dominio 
                                for patron in config.PATRONES_DOMINIO_SOSPECHOSO
                            )
                            
                            # Verificar si es un dominio legítimo
                            es_legitimo = any(
                                legitimo in dominio 
                                for legitimo in config.DOMINIOS_LEGITIMOS
                            )
                            
                            # Solo agregar si es sospechoso Y NO es legítimo
                            if es_sospechoso and not es_legitimo:
                                if dominio not in self.dominios_sospechosos:
                                    self.dominios_sospechosos[dominio] = getattr(pkt, 'number', 'N/A')
        except:
            pass  # Ignorar errores y continuar
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Devuelve:
            dict: Diccionario con la lista de dominios sospechosos (objetos con nombre y paquete)
        """
        # Convertir a lista de diccionarios para el reporteador
        lista_dominios = [
            {'dominio': dominio, 'paquete': paquete}
            for dominio, paquete in self.dominios_sospechosos.items()
        ]
        
        return {
            'dominios_auth_falsos': lista_dominios
        }
