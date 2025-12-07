"""
EXTRACTOR DE TRANSFERENCIAS DE DATOS GRANDES (EXFILTRACIÓN)
===========================================================

Este módulo monitoriza el volumen de datos transferidos entre hosts
para detectar posible exfiltración de información o descargas masivas.
"""

from collections import defaultdict
import config


class ExtractorTransferencias:
    """
    Detecta transferencias de datos inusualmente grandes.
    """
    
    def __init__(self):
        """
        Inicializa el extractor.
        flujos: {(ip_src, ip_dst): bytes_transferidos}
        """
        self.flujos = defaultdict(int)
        # Guardar el primer paquete detectado para cada flujo
        self.primer_paquete_flujo = {}
    
    def procesar_paquete(self, pkt):
        """
        Contabiliza el tamaño de los paquetes para detectar flujos grandes.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            if hasattr(pkt, 'ip'):
                ip_src = str(pkt.ip.src)
                ip_dst = str(pkt.ip.dst)
                length = int(pkt.length)
                
                # Por ahora registramos todo y filtramos al final si es necesario
                
                flujo = (ip_src, ip_dst)
                self.flujos[flujo] += length
                
                # Guardar el primer paquete si no existe
                if flujo not in self.primer_paquete_flujo:
                    self.primer_paquete_flujo[flujo] = getattr(pkt, 'number', 'N/A')
        except:
            pass
    
    def obtener_resultados(self):
        """
        Obtiene los flujos que superan el umbral definido.
        
        Devuelve:
            dict: Diccionario con transferencias grandes detectadas
        """
        transferencias_grandes = []
        
        for (origen, destino), bytes_total in self.flujos.items():
            if bytes_total > config.UMBRAL_TRANSFERENCIA_BYTES:
                # Convertir a MB para lectura humana
                mb_total = round(bytes_total / (1024 * 1024), 2)
                
                # Determinar dirección (Subida vs Bajada)
                # Asumimos que IPs privadas son internas
                es_origen_interno = any(origen.startswith(p) for p in config.PREFIJOS_IP_PRIVADA)
                es_destino_interno = any(destino.startswith(p) for p in config.PREFIJOS_IP_PRIVADA)
                
                tipo = "Interno"
                if es_origen_interno and not es_destino_interno:
                    tipo = "Posible Exfiltración (Subida)"
                elif not es_origen_interno and es_destino_interno:
                    tipo = "Descarga (Bajada)"
                
                transferencias_grandes.append({
                    'origen': origen,
                    'destino': destino,
                    'bytes': bytes_total,
                    'megabytes': mb_total,
                    'tipo': tipo,
                    'paquete_inicio': self.primer_paquete_flujo.get((origen, destino), 'N/A')
                })
        
        # Ordenar por tamaño (mayor a menor)
        transferencias_grandes.sort(key=lambda x: x['bytes'], reverse=True)
        
        return {
            'transferencias_grandes': transferencias_grandes
        }
