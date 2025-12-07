"""
EXTRACTOR DE HOSTNAMES
======================

Este módulo extrae nombres de host (hostnames) del tráfico NetBIOS,
que es el protocolo de Windows para nombres de red.
"""

import config


class ExtractorHostname:
    """
    Extrae nombres de host de paquetes NetBIOS Name Service.
    """
    
    def __init__(self):
        """Inicializa el extractor con un diccionario de hostnames."""
        # Diccionario: hostname -> número de paquete
        self.hostnames_dict = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete NetBIOS para extraer nombres de host.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # NetBIOS Name Service: Protocolo de Windows para nombres de red
            if hasattr(pkt, 'nbns'):
                todos_campos = pkt.nbns._all_fields
                
                # Buscar en las secciones de consultas y registros adicionales
                for seccion in ['Queries', 'Additional records']:
                    if seccion in todos_campos:
                        for clave, valor in todos_campos[seccion].items():
                            if isinstance(valor, dict) and 'nbns.name' in valor:
                                nombre_crudo = valor['nbns.name']
                                
                                # Limpiar el nombre
                                # Formato: "NOMBRE-PC<00>" o "NOMBRE-PC<00> (Workstation)"
                                if '<' in nombre_crudo:
                                    hostname = nombre_crudo.split('<')[0].strip()
                                    
                                    # Solo agregar si es un nombre válido
                                    # Excluir nombres genéricos como WORKGROUP
                                    if (hostname and 
                                        '.' not in hostname and 
                                        hostname.upper() not in config.HOSTNAMES_GENERICOS):
                                        
                                        if hostname not in self.hostnames_dict:
                                            self.hostnames_dict[hostname] = getattr(pkt, 'number', 'N/A')
        except:
            pass  # Ignorar errores en este paquete
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Devuelve:
            dict: Diccionario con la lista de hostnames encontrados (objetos con nombre y paquete)
        """
        # Convertir a lista de diccionarios para el reporteador
        lista_hostnames = [
            {'nombre': nombre, 'paquete': paquete}
            for nombre, paquete in self.hostnames_dict.items()
        ]
        
        return {
            'hostnames': lista_hostnames
        }
