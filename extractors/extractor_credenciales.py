"""
EXTRACTOR DE CREDENCIALES
=========================

Este módulo busca credenciales enviadas en texto plano a través de
protocolos no cifrados como HTTP, FTP, POP3, IMAP y Telnet.
"""

import base64

class ExtractorCredenciales:
    """
    Detecta credenciales en texto plano en varios protocolos.
    """
    
    def __init__(self):
        self.credenciales_encontradas = []
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para buscar credenciales.
        """
        try:
            # HTTP Basic Auth
            if hasattr(pkt, 'http') and hasattr(pkt.http, 'authorization'):
                auth = pkt.http.authorization
                if 'Basic' in auth:
                    try:
                        # Formato: "Basic <base64>"
                        b64_str = auth.split(' ')[1]
                        decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                        self._agregar_credencial('HTTP', decoded, pkt)
                    except:
                        pass

            # FTP
            if hasattr(pkt, 'ftp'):
                if hasattr(pkt.ftp, 'request_command'):
                    cmd = str(pkt.ftp.request_command).upper()
                    arg = getattr(pkt.ftp, 'request_arg', '')
                    if cmd == 'USER':
                        self._agregar_credencial('FTP', f"Usuario: {arg}", pkt)
                    elif cmd == 'PASS':
                        self._agregar_credencial('FTP', f"Contraseña: {arg}", pkt)

            # POP3
            if hasattr(pkt, 'pop'):
                if hasattr(pkt.pop, 'request_command'):
                    cmd = str(pkt.pop.request_command).upper()
                    param = getattr(pkt.pop, 'request_parameter', '')
                    if cmd == 'USER':
                        self._agregar_credencial('POP3', f"Usuario: {param}", pkt)
                    elif cmd == 'PASS':
                        self._agregar_credencial('POP3', f"Contraseña: {param}", pkt)

            # IMAP
            if hasattr(pkt, 'imap'):
                if hasattr(pkt.imap, 'request_command'):
                    cmd = str(pkt.imap.request_command).upper()
                    if cmd == 'LOGIN':
                        # IMAP suele enviar "LOGIN user pass" en una línea o argumentos separados
                        # Pyshark a veces lo pone en request_arg
                        line = getattr(pkt.imap, 'request_arg', '')
                        self._agregar_credencial('IMAP', f"Login info: {line}", pkt)

            # Telnet (muy básico, solo busca strings comunes en data)
            if hasattr(pkt, 'telnet') and hasattr(pkt.telnet, 'data'):
                data = str(pkt.telnet.data)
                # Esto es muy ruidoso, mejor solo si detectamos patrones claros o lo dejamos como "Tráfico Telnet detectado"
                # Por ahora, para no llenar de basura, lo omitiremos o seremos muy específicos.
                # Dejaremos Telnet fuera por ahora para evitar falsos positivos masivos con datos binarios.
                pass

        except Exception:
            pass

    def _agregar_credencial(self, protocolo, info, pkt):
        """Agrega una credencial encontrada a la lista."""
        ip_src = getattr(pkt.ip, 'src', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
        ip_dst = getattr(pkt.ip, 'dst', 'Desconocido') if hasattr(pkt, 'ip') else 'Desconocido'
        num_paquete = getattr(pkt, 'number', 'N/A')
        
        self.credenciales_encontradas.append({
            'protocolo': protocolo,
            'info': info,
            'origen': ip_src,
            'destino': ip_dst,
            'paquete': num_paquete
        })

    def obtener_resultados(self):
        return {
            'credenciales_expuestas': self.credenciales_encontradas
        }
