"""
EXTRACTOR DE CONEXIONES A PUERTOS SOSPECHOSOS
==============================================

Este módulo detecta conexiones a puertos comúnmente utilizados
por malware para comunicación C2 o actividades maliciosas.
"""

import config


class ExtractorPuertosSospechosos:
    """
    Detecta conexiones a puertos conocidos por ser usados por malware.
    """
    
    def __init__(self):
        """Inicializa el extractor con un diccionario de conexiones sospechosas."""
        # Diccionario: (ip, puerto) -> objeto conexión
        self.conexiones_sospechosas = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete TCP/UDP para detectar conexiones a puertos sospechosos.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            puerto_destino = None
            ip_destino = None
            protocolo = None
            
            # Analizar paquetes TCP
            if hasattr(pkt, 'tcp'):
                puerto_destino = int(pkt.tcp.dstport)
                protocolo = 'TCP'
            # Analizar paquetes UDP
            elif hasattr(pkt, 'udp'):
                puerto_destino = int(pkt.udp.dstport)
                protocolo = 'UDP'
            
            # Obtener IP de destino
            if hasattr(pkt, 'ip'):
                ip_destino = str(pkt.ip.dst)
            
            if puerto_destino and ip_destino:
                # Verificar si el puerto está en la lista de sospechosos
                if puerto_destino in config.PUERTOS_SOSPECHOSOS:
                    # Excluir IPs privadas (red local)
                    if not ip_destino.startswith(config.PREFIJOS_IP_PRIVADA):
                        clave = (ip_destino, puerto_destino)
                        
                        if clave not in self.conexiones_sospechosas:
                            info_puerto = config.PUERTOS_SOSPECHOSOS[puerto_destino]
                            self.conexiones_sospechosas[clave] = {
                                'ip': ip_destino,
                                'puerto': puerto_destino,
                                'protocolo': protocolo,
                                'descripcion': info_puerto,
                                'paquete': getattr(pkt, 'number', 'N/A')
                            }
        except:
            pass
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con lista de conexiones a puertos sospechosos
        """
        return {
            'conexiones_puertos_sospechosos': list(self.conexiones_sospechosas.values())
        }
