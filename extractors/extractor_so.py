"""
EXTRACTOR DE INFORMACIÓN DEL SISTEMA OPERATIVO
===============================================

Este módulo extrae información sobre el sistema operativo y navegador
del equipo infectado, analizando User-Agents HTTP y protocolos SMB.
También genera CPEs (Common Platform Enumeration).
"""

import re
from typing import Optional
import config


class ExtractorSO:
    """
    Extrae información del sistema operativo y navegador,
    y genera CPEs correspondientes.
    """
    
    def __init__(self):
        """Inicializa el extractor con estructuras vacías."""
        # Información del sistema operativo para generar CPE
        self.info_so: dict[str, Optional[str]] = {
            'nombre_so': None,           # Nombre del sistema operativo
            'version_so': None,          # Versión del SO
            'navegador': None,           # Navegador web usado
            'version_navegador': None    # Versión del navegador
        }
        
        # User-Agents encontrados (para referencia)
        self.user_agents = set()
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para extraer información del SO y navegador.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        # Intentar extraer de HTTP User-Agent
        self._extraer_de_http(pkt)
        
        # Intentar extraer de SMB
        self._extraer_de_smb(pkt)
    
    def _extraer_de_http(self, pkt):
        """
        Extrae información del SO y navegador del User-Agent HTTP.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            if hasattr(pkt, 'http'):
                todos_campos = pkt.http._all_fields
                
                # Extraer User-Agent para identificar sistema operativo y navegador
                # User-Agent = texto que identifica el navegador y SO del usuario
                if 'http.user_agent' in todos_campos:
                    user_agent = str(todos_campos['http.user_agent'])
                    self.user_agents.add(user_agent)
                    
                    # Detectar versión de Windows del User-Agent
                    self._detectar_version_windows(user_agent)
                    
                    # Detectar navegador
                    self._detectar_navegador(user_agent)
        except:
            pass
    
    def _detectar_version_windows(self, user_agent):
        """
        Detecta la versión de Windows del User-Agent.
        
        Args:
            user_agent: String del User-Agent HTTP
        """
        for version_nt, (nombre_so, version_so) in config.VERSIONES_WINDOWS.items():
            if version_nt in user_agent:
                self.info_so['nombre_so'] = nombre_so
                self.info_so['version_so'] = version_so
                break
    
    def _detectar_navegador(self, user_agent):
        """
        Detecta el navegador y su versión del User-Agent.
        
        Args:
            user_agent: String del User-Agent HTTP
        """
        # Buscar qué navegador se está usando
        if 'Edg/' in user_agent or 'Edge/' in user_agent:
            self.info_so['navegador'] = 'Microsoft Edge'
            # Buscar la versión del navegador (ej: Edge/96.0)
            match = re.search(r'Edg?e?/(\d+\.\d+)', user_agent)
            if match:
                self.info_so['version_navegador'] = match.group(1)
        
        elif 'Chrome/' in user_agent and 'Edg' not in user_agent:
            self.info_so['navegador'] = 'Google Chrome'
            match = re.search(r'Chrome/(\d+\.\d+)', user_agent)
            if match:
                self.info_so['version_navegador'] = match.group(1)
        
        elif 'Firefox/' in user_agent:
            self.info_so['navegador'] = 'Mozilla Firefox'
            match = re.search(r'Firefox/(\d+\.\d+)', user_agent)
            if match:
                self.info_so['version_navegador'] = match.group(1)
    
    def _extraer_de_smb(self, pkt):
        """
        Extrae información del SO de paquetes SMB.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # SMB = Protocolo de compartición de archivos de Windows
            # Contiene información sobre el sistema operativo
            if hasattr(pkt, 'smb') or hasattr(pkt, 'smb2'):
                # Usar SMB o SMB2 dependiendo de cuál esté presente
                capa_smb = pkt.smb if hasattr(pkt, 'smb') else pkt.smb2
                todos_campos = capa_smb._all_fields
                
                # Buscar información del sistema operativo nativo
                if 'smb.native_os' in todos_campos:
                    so_nativo = str(todos_campos['smb.native_os'])
                    if 'Windows' in so_nativo:
                        self.info_so['nombre_so'] = 'Windows'
                        # Intentar extraer la versión
                        if '10' in so_nativo:
                            self.info_so['version_so'] = '10'
                        elif '8.1' in so_nativo:
                            self.info_so['version_so'] = '8.1'
                        elif '7' in so_nativo:
                            self.info_so['version_so'] = '7'
        except:
            pass
    
    def _generar_cpes(self):
        """
        Genera CPEs (Common Platform Enumeration) basados en la información recopilada.
        
        Returns:
            list: Lista de diccionarios con información de CPE
        """
        cpes = []
        
        # CPE del sistema operativo
        if self.info_so['nombre_so'] and self.info_so['version_so']:
            cpe_so = f"cpe:/o:microsoft:windows_{self.info_so['version_so'].replace('.', '_')}"
            cpes.append({
                'tipo': 'Operating System',
                'cpe': cpe_so,
                'descripcion': f"Microsoft Windows {self.info_so['version_so']}"
            })
        elif self.info_so['nombre_so']:
            cpes.append({
                'tipo': 'Operating System',
                'cpe': 'cpe:/o:microsoft:windows',
                'descripcion': 'Microsoft Windows (versión no determinada)'
            })
        
        # CPE del navegador
        if self.info_so['navegador']:
            nombre_navegador = self.info_so['navegador'].lower().replace(' ', '_')
            cpe_navegador = None
            
            if 'edge' in nombre_navegador:
                cpe_navegador = "cpe:/a:microsoft:edge"
                if self.info_so['version_navegador']:
                    cpe_navegador += f":{self.info_so['version_navegador']}"
            
            elif 'chrome' in nombre_navegador:
                cpe_navegador = "cpe:/a:google:chrome"
                if self.info_so['version_navegador']:
                    cpe_navegador += f":{self.info_so['version_navegador']}"
            
            elif 'firefox' in nombre_navegador:
                cpe_navegador = "cpe:/a:mozilla:firefox"
                if self.info_so['version_navegador']:
                    cpe_navegador += f":{self.info_so['version_navegador']}"
            
            if cpe_navegador:
                cpes.append({
                    'tipo': 'Application',
                    'cpe': cpe_navegador,
                    'descripcion': f"{self.info_so['navegador']}" + 
                                 (f" {self.info_so['version_navegador']}" 
                                  if self.info_so['version_navegador'] else "")
                })
        
        return cpes
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con CPEs generados
        """
        return {
            'cpes': self._generar_cpes()
        }
