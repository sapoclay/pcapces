"""
EXTRACTOR DE LATENCIA RTT
=========================

Este módulo analiza el tiempo de ida y vuelta (RTT) en conexiones TCP
para detectar problemas de rendimiento o latencia en la red.
"""

import config

class ExtractorRTT:
    """
    Detecta alta latencia (RTT) en conexiones TCP.
    """
    
    def __init__(self):
        self.conexiones_lentas = []
    
    def procesar_paquete(self, pkt):
        try:
            if hasattr(pkt, 'tcp'):
                # Pyshark/Tshark calcula analysis_ack_rtt si está habilitado
                if hasattr(pkt.tcp, 'analysis_ack_rtt'):
                    rtt = float(pkt.tcp.analysis_ack_rtt)
                    
                    if rtt > config.UMBRAL_RTT_LATENCIA:
                        ip_src = getattr(pkt.ip, 'src', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
                        ip_dst = getattr(pkt.ip, 'dst', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
                        port_dst = getattr(pkt.tcp, 'dstport', 'N/A')
                        num_paquete = getattr(pkt, 'number', 'N/A')
                        
                        self.conexiones_lentas.append({
                            'origen': ip_src,
                            'destino': ip_dst,
                            'puerto': port_dst,
                            'rtt': rtt,
                            'paquete': num_paquete
                        })
        except Exception:
            pass

    def obtener_resultados(self):
        # Ordenar por RTT descendente y tomar top 10 para no saturar
        lentas_ordenadas = sorted(self.conexiones_lentas, key=lambda x: x['rtt'], reverse=True)[:10]
        
        return {
            'conexiones_lentas': lentas_ordenadas
        }
