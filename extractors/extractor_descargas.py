"""
EXTRACTOR DE DESCARGAS DE EJECUTABLES
======================================

Este módulo detecta la descarga de archivos potencialmente peligrosos
(ejecutables, scripts, etc.) analizando el tráfico HTTP/SMB.
"""

import config


class ExtractorDescargas:
    """
    Detecta descargas de archivos con extensiones peligrosas.
    """
    
    def __init__(self):
        """Inicializa el extractor."""
        self.descargas_detectadas = []
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para detectar transferencias de archivos sospechosos.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # Detección en HTTP
            if hasattr(pkt, 'http'):
                self._analizar_http(pkt)
                
            # Detección en SMB (Server Message Block) - Común en redes Windows
            if hasattr(pkt, 'smb') or hasattr(pkt, 'smb2'):
                self._analizar_smb(pkt)
                
        except Exception:
            pass
            
    def _analizar_http(self, pkt):
        """Analiza paquetes HTTP buscando URIs o Content-Types sospechosos."""
        try:
            todos_campos = pkt.http._all_fields
            
            # Verificar URI de la petición
            # pyshark a veces usa http.request.uri y otras http.request_uri
            uri = None
            if 'http.request.uri' in todos_campos:
                uri = str(todos_campos['http.request.uri']).lower()
            elif hasattr(pkt.http, 'request_uri'):
                uri = str(pkt.http.request_uri).lower()
                
            if uri:
                # Buscar extensiones peligrosas en la URI
                for ext in config.EXTENSIONES_PELIGROSAS:
                    # Detectar si termina en la extensión o si la extensión está seguida de ? o /
                    if uri.endswith(ext) or f"{ext}?" in uri or f"{ext}/" in uri:
                        self._registrar_descarga(
                            pkt, 
                            archivo=uri.split('/')[-1].split('?')[0],
                            protocolo="HTTP",
                            info=f"Solicitud GET de archivo {ext}"
                        )
                        return

            # Verificar Content-Type en la respuesta
            content_type = None
            if 'http.content_type' in todos_campos:
                content_type = str(todos_campos['http.content_type']).lower()
            elif hasattr(pkt.http, 'content_type'):
                content_type = str(pkt.http.content_type).lower()
                
            if content_type and content_type in config.MIME_TYPES_PELIGROSOS:
                filename = "desconocido"
                
                # Intentar extraer nombre del archivo del header Content-Disposition
                content_disposition = None
                if 'http.content_disposition' in todos_campos:
                    content_disposition = str(todos_campos['http.content_disposition'])
                elif hasattr(pkt.http, 'content_disposition'):
                    content_disposition = str(pkt.http.content_disposition)
                    
                if content_disposition:
                    import re
                    match = re.search(r'filename="?([^";]+)"?', content_disposition)
                    if match:
                        filename = match.group(1)
                
                self._registrar_descarga(
                    pkt,
                    archivo=filename,
                    protocolo="HTTP",
                    info=f"Content-Type sospechoso: {content_type}"
                )
        except:
            pass

    def _analizar_smb(self, pkt):
        """Analiza paquetes SMB buscando nombres de archivos."""
        try:
            filename = None
            # SMB2 Create Request / Read Request
            if hasattr(pkt, 'smb2'):
                if hasattr(pkt.smb2, 'filename'):
                    filename = str(pkt.smb2.filename)
            
            if filename:
                filename_lower = filename.lower()
                for ext in config.EXTENSIONES_PELIGROSAS:
                    if filename_lower.endswith(ext):
                        self._registrar_descarga(
                            pkt,
                            archivo=filename,
                            protocolo="SMB",
                            info=f"Acceso a archivo {ext} vía red interna"
                        )
        except:
            pass

    def _registrar_descarga(self, pkt, archivo, protocolo, info):
        """Registra una descarga detectada evitando duplicados."""
        origen = str(pkt.ip.src) if hasattr(pkt, 'ip') else "Desconocido"
        destino = str(pkt.ip.dst) if hasattr(pkt, 'ip') else "Desconocido"
        numero_paquete = getattr(pkt, 'number', 'N/A')
        
        # Crear un identificador único para evitar spam del mismo archivo en múltiples paquetes
        # Usamos (archivo, origen, destino) como clave única
        clave_unica = (archivo, origen, destino)
        
        # Verificar si ya detectamos esta descarga (para no repetirla)
        ya_detectado = any(
            d['archivo'] == archivo and d['origen'] == origen and d['destino'] == destino
            for d in self.descargas_detectadas
        )
        
        if not ya_detectado:
            self.descargas_detectadas.append({
                'archivo': archivo,
                'origen': origen,
                'destino': destino,
                'protocolo': protocolo,
                'info': info,
                'paquete': numero_paquete
            })
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con lista de descargas detectadas
        """
        return {
            'descargas_sospechosas': self.descargas_detectadas
        }
