"""
EXTRACTOR DE USER-AGENTS
========================

Este módulo analiza las cabeceras User-Agent en tráfico HTTP
para detectar agentes de usuario sospechosos, vacíos o de herramientas de hacking.
"""

import config

class ExtractorUserAgents:
    """
    Detecta User-Agents que suenan a cochiquera.
    """
    
    def __init__(self):
        self.uas_sospechosos = []
        # Lista básica de UAs sospechosos conocidos
        self.blacklist = [
            'sqlmap', 'nikto', 'nmap', 'hydra', 'curl', 'wget', 'python-requests', 
            'powershell', 'apache-httpclient', 'go-http-client'
        ]
    
    def procesar_paquete(self, pkt):
        try:
            if hasattr(pkt, 'http') and hasattr(pkt.http, 'user_agent'):
                ua = str(pkt.http.user_agent)
                ua_lower = ua.lower()
                
                es_sospechoso = False
                motivo = ""
                
                # Chequeo 1: UA vacío (raro en navegadores modernos)
                if not ua:
                    es_sospechoso = True
                    motivo = "User-Agent vacío"
                
                # Chequeo 2: UA muy corto
                elif len(ua) < config.UA_MIN_LONGITUD:
                    es_sospechoso = True
                    motivo = "User-Agent muy corto"
                
                # Chequeo 3: Herramientas conocidas
                else:
                    for bad_ua in self.blacklist:
                        if bad_ua in ua_lower:
                            es_sospechoso = True
                            motivo = f"Herramienta conocida ({bad_ua})"
                            break
                
                if es_sospechoso:
                    self._agregar_ua(ua, motivo, pkt)
                    
        except Exception:
            pass

    def _agregar_ua(self, ua, motivo, pkt):
        ip_src = getattr(pkt.ip, 'src', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
        num_paquete = getattr(pkt, 'number', 'N/A')
        
        # Evitar duplicados exactos (mismo UA, misma IP) para no saturar
        # Queremos saber si ocurre muchas veces.
        # Por simplicidad, guardamos todo y el reporteador puede resumir o mostrar los primeros N.
        
        self.uas_sospechosos.append({
            'user_agent': ua,
            'motivo': motivo,
            'origen': ip_src,
            'paquete': num_paquete
        })

    def obtener_resultados(self):
        return {
            'user_agents_anomalos': self.uas_sospechosos
        }
