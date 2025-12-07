"""
EXTRACTOR DE ANOMALÍAS ARP
==========================

Este módulo analiza el tráfico ARP para detectar comportamientos
anómalos como escaneos ARP excesivos o posibles tormentas de broadcast.
"""

import config

class ExtractorARP:
    """
    Detecta anomalías en tráfico ARP.
    """
    
    def __init__(self):
        # Conteo de solicitudes por IP origen
        self.solicitudes_por_ip = {}
        self.anomalias = []
    
    def procesar_paquete(self, pkt):
        try:
            if hasattr(pkt, 'arp'):
                # Opcode 1 = Request, 2 = Reply
                opcode = getattr(pkt.arp, 'opcode', '0')
                
                if opcode == '1': # Request
                    ip_src = getattr(pkt.arp, 'src_proto_ipv4', None)
                    if ip_src:
                        self.solicitudes_por_ip[ip_src] = self.solicitudes_por_ip.get(ip_src, 0) + 1
                        
        except Exception:
            pass

    def obtener_resultados(self):
        # Analizar contadores al final
        for ip, count in self.solicitudes_por_ip.items():
            if count > config.UMBRAL_ARP_SOLICITUDES:
                self.anomalias.append({
                    'ip': ip,
                    'tipo': 'Solicitudes ARP Excesivas',
                    'cantidad': count,
                    'mensaje': f"La IP {ip} envió {count} solicitudes ARP (posible escaneo)"
                })
                
        return {
            'anomalias_arp': self.anomalias
        }
