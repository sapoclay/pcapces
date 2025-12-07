"""
EXTRACTOR DE NOMBRES DE USUARIO
================================

Este módulo extrae nombres de usuario del tráfico de red,
específicamente de protocolos Kerberos y LDAP/CLDAP.
"""

import config


class ExtractorUsuario:
    """
    Extrae nombres de usuario de paquetes Kerberos y LDAP.
    """
    
    def __init__(self):
        """Inicializa el extractor con un diccionario de usuarios."""
        # Diccionario: usuario -> número de paquete
        self.usuarios_dict = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para extraer nombres de usuario.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        # Intentar extraer de Kerberos
        self._extraer_de_kerberos(pkt)
        
        # Intentar extraer de LDAP/CLDAP
        self._extraer_de_ldap(pkt)
        
    def _agregar_usuario(self, usuario, pkt):
        """Agrega un usuario detectado si no existe."""
        if usuario and usuario not in self.usuarios_dict:
            self.usuarios_dict[usuario] = getattr(pkt, 'number', 'N/A')
    
    def _extraer_de_kerberos(self, pkt):
        """
        Extrae nombres de usuario de paquetes Kerberos.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # Kerberos: protocolo de autenticación de Windows
            if hasattr(pkt, 'kerberos'):
                todos_campos = pkt.kerberos._all_fields
                
                # Función auxiliar para buscar el nombre de usuario
                # en estructuras de datos anidadas de diccionarios
                def buscar_cname(obj):
                    if isinstance(obj, dict):
                        for clave, valor in obj.items():
                            if clave == 'kerberos.CNameString':
                                return valor
                            resultado = buscar_cname(valor)
                            if resultado:
                                return resultado
                    elif isinstance(obj, list):
                        for item in obj:
                            resultado = buscar_cname(item)
                            if resultado:
                                return resultado
                    return None
                
                usuario = buscar_cname(todos_campos)
                if usuario:
                    usuario = str(usuario)
                    # Filtrar nombres de máquina (terminan en $)
                    if not usuario.endswith(config.SUFIJO_NOMBRE_MAQUINA):
                        self._agregar_usuario(usuario, pkt)
        except:
            pass
    
    def _extraer_de_ldap(self, pkt):
        """
        Extrae nombres de usuario de paquetes LDAP/CLDAP.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # LDAP/CLDAP: Protocolo de directorio (Active Directory de Windows)
            if hasattr(pkt, 'cldap') or hasattr(pkt, 'ldap'):
                # Intentar con CLDAP primero
                capa_ldap = pkt.cldap if hasattr(pkt, 'cldap') else pkt.ldap
                todos_campos = capa_ldap._all_fields
                
                # Función recursiva para buscar username en estructuras anidadas
                def buscar_usuario_ldap(obj, profundidad=0):
                    """Busca recursivamente el campo username en LDAP"""
                    if profundidad > config.MAX_PROFUNDIDAD_RECURSION:
                        return None
                    
                    if isinstance(obj, dict):
                        # Buscar directamente el campo username
                        for clave, valor in obj.items():
                            if 'username' in clave.lower():
                                return valor
                        # Buscar recursivamente en los valores
                        for clave, valor in obj.items():
                            resultado = buscar_usuario_ldap(valor, profundidad + 1)
                            if resultado:
                                return resultado
                    elif isinstance(obj, list):
                        for item in obj:
                            resultado = buscar_usuario_ldap(item, profundidad + 1)
                            if resultado:
                                return resultado
                    return None
                
                usuario = buscar_usuario_ldap(todos_campos)
                if usuario:
                    usuario = str(usuario)
                    # Limpiar el username (puede venir como <Root> o similar)
                    usuario = usuario.strip('<>').strip()
                    if usuario:
                        self._agregar_usuario(usuario, pkt)
        except:
            pass
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con la lista de usuarios encontrados (objetos con nombre y paquete)
        """
        # Convertir a lista de diccionarios para el reporteador
        lista_usuarios = [
            {'nombre': nombre, 'paquete': paquete}
            for nombre, paquete in self.usuarios_dict.items()
        ]
        
        return {
            'usuarios': lista_usuarios
        }
