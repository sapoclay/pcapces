"""
EXTRACTOR DE ESCANEO DE PUERTOS (PORT SCANNING)
================================================

Este módulo detecta actividad de escaneo de puertos analizando
patrones de conexiones: múltiples intentos a diferentes puertos
desde una misma IP origen hacia un mismo destino.
"""

from collections import defaultdict
import config


class ExtractorEscaneoPuertos:
    """
    Detecta escaneos de puertos basándose en patrones de conexión.
    """
    
    def __init__(self):
        """
        Inicializa el extractor con estructuras para rastrear conexiones.
        
        conexiones_por_par: {(ip_origen, ip_destino): set(puertos)}
        """
        self.conexiones_por_par = defaultdict(set)
        # También rastreamos paquetes SYN sin respuesta (indicador de escaneo)
        self.paquetes_syn = defaultdict(set)
        # Guardar el primer paquete detectado para cada par de IPs
        self.primer_paquete_par = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete TCP para detectar patrones de escaneo.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            if hasattr(pkt, 'tcp') and hasattr(pkt, 'ip'):
                ip_origen = str(pkt.ip.src)
                ip_destino = str(pkt.ip.dst)
                puerto_destino = int(pkt.tcp.dstport)
                
                # Rastrear todas las conexiones TCP por par de IPs
                par_ips = (ip_origen, ip_destino)
                self.conexiones_por_par[par_ips].add(puerto_destino)
                
                # Guardar el primer paquete si no existe
                if par_ips not in self.primer_paquete_par:
                    self.primer_paquete_par[par_ips] = getattr(pkt, 'number', 'N/A')
                
                # Detectar paquetes SYN (inicio de conexión)
                # Flag SYN = 0x02, SYN+ACK = 0x12
                if hasattr(pkt.tcp, 'flags'):
                    flags = str(pkt.tcp.flags)
                    # Paquete SYN puro (solo SYN, sin ACK)
                    if flags == '0x00000002' or flags == '0x0002':
                        self.paquetes_syn[par_ips].add(puerto_destino)
        except:
            pass
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis de escaneo de puertos.
        
        Returns:
            dict: Diccionario con información sobre escaneos detectados
        """
        escaneos_detectados = []
        
        for (ip_origen, ip_destino), puertos in self.conexiones_por_par.items():
            num_puertos = len(puertos)
            
            # Si hay conexiones a muchos puertos diferentes, es probable escaneo
            if num_puertos >= config.UMBRAL_ESCANEO_PUERTOS:
                # Verificar si hay muchos paquetes SYN (indicador más fuerte)
                syn_count = len(self.paquetes_syn.get((ip_origen, ip_destino), set()))
                
                # Determinar el tipo de escaneo
                if syn_count >= config.UMBRAL_ESCANEO_PUERTOS:
                    tipo_escaneo = "SYN Scan (Escaneo sigiloso)"
                else:
                    tipo_escaneo = "TCP Connect Scan"
                
                # Determinar severidad
                if num_puertos >= 100:
                    severidad = "ALTA"
                elif num_puertos >= 50:
                    severidad = "MEDIA"
                else:
                    severidad = "BAJA"
                
                escaneos_detectados.append({
                    'ip_origen': ip_origen,
                    'ip_destino': ip_destino,
                    'puertos_escaneados': num_puertos,
                    'tipo_escaneo': tipo_escaneo,
                    'severidad': severidad,
                    'paquete_inicio': self.primer_paquete_par.get((ip_origen, ip_destino), 'N/A'),
                    'muestra_puertos': sorted(list(puertos))[:10]  # Primeros 10 puertos
                })
        
        # Ordenar por número de puertos escaneados (más grave primero)
        escaneos_detectados.sort(key=lambda x: x['puertos_escaneados'], reverse=True)
        
        return {
            'escaneos_puertos': escaneos_detectados
        }
