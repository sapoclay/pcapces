"""
EXTRACTOR DE ERRORES HTTP
=========================

Este módulo analiza el tráfico HTTP para detectar respuestas de error
(códigos 4xx y 5xx) que puedan indicar intentos fallidos, vulnerabilidades
o problemas en el servidor.
"""

class ExtractorErrores:
    """
    Detecta respuestas HTTP con códigos de error.
    """
    
    def __init__(self):
        # Diccionario para agrupar errores:
        # Clave: (codigo, descripcion, servidor, origen, destino, uri)
        # Valor: {'count': int, 'paquete_inicio': str}
        self.errores_agrupados = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para buscar códigos de respuesta HTTP de error.
        """
        try:
            if hasattr(pkt, 'http'):
                # Verificar si es una respuesta
                codigo = None
                
                if hasattr(pkt.http, 'response_code'):
                    codigo = int(pkt.http.response_code)
                elif hasattr(pkt.http, '_all_fields'):
                    # Fallback para modo JSON donde el código está anidado
                    for key, val in pkt.http._all_fields.items():
                        if isinstance(val, dict) and 'http.response.code' in val:
                            try:
                                codigo = int(val['http.response.code'])
                                break
                            except: pass
                
                if codigo is not None:
                    # Códigos 4xx (Cliente) y 5xx (Servidor)
                    if 400 <= codigo < 600:
                        ip_src = getattr(pkt.ip, 'src', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
                        ip_dst = getattr(pkt.ip, 'dst', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
                        num_paquete = getattr(pkt, 'number', 'N/A')
                        server = getattr(pkt.http, 'server', 'Desconocido')
                        
                        # Intentar obtener URI
                        uri = "N/A"
                        if hasattr(pkt.http, 'request_uri'):
                            uri = pkt.http.request_uri
                        elif hasattr(pkt.http, '_all_fields'):
                             for key, val in pkt.http._all_fields.items():
                                if isinstance(val, dict) and 'http.request.uri' in val:
                                    uri = val['http.request.uri']
                                    break
                        
                        descripcion = getattr(pkt.http, 'response_phrase', 'Error HTTP')
                        
                        clave = (codigo, descripcion, server, ip_src, ip_dst, uri)
                        
                        if clave not in self.errores_agrupados:
                            self.errores_agrupados[clave] = {
                                'count': 0,
                                'paquete_inicio': num_paquete
                            }
                        
                        self.errores_agrupados[clave]['count'] += 1

        except Exception:
            pass

    def obtener_resultados(self):
        lista_errores = []
        for (codigo, descripcion, server, ip_src, ip_dst, uri), datos in self.errores_agrupados.items():
            lista_errores.append({
                'codigo': codigo,
                'descripcion': descripcion,
                'servidor': server,
                'origen': ip_src,
                'destino': ip_dst,
                'uri': uri,
                'paquete': datos['paquete_inicio'],
                'conteo': datos['count']
            })
            
        return {
            'errores_http': lista_errores
        }
