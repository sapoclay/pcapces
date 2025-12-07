"""
EXTRACTOR DE DIRECCIONES IP Y MAC
==================================

Este módulo extrae direcciones IP y MAC del tráfico de red,
identifica la IP más activa (probablemente infectada) y
asocia direcciones MAC con sus IPs correspondientes.
"""

from collections import Counter
import config


class ExtractorIP:
    """
    Extrae y analiza direcciones IP y MAC de paquetes de red.
    """
    
    def __init__(self):
        """Inicializa el extractor con estructuras de datos vacías."""
        # Cuenta cuántas veces aparece cada dirección IP
        self.contador_ip = Counter()
        
        # Diccionario que asocia direcciones MAC con direcciones IP
        # Formato: mac -> {'ip': ip, 'paquete': paquete}
        self.mac_a_ip = {}
        
        # Diccionario para guardar el primer paquete donde se vio cada IP
        self.primera_aparicion = {}
    
    def procesar_paquete(self, pkt):
        """
        Procesa un paquete para extraer información de IP y MAC.
        
        Args:
            pkt: Paquete de pyshark a analizar
        """
        try:
            # Verificar si el paquete tiene información IP
            if hasattr(pkt, 'ip'):
                src = pkt.ip.src  # IP de quien envía
                
                # Solo contar IPs privadas (red local)
                if src.startswith(config.PREFIJOS_IP_PRIVADA):
                    self.contador_ip[src] += 1
                    
                    # Guardar el primer paquete donde se vio esta IP
                    if src not in self.primera_aparicion:
                        self.primera_aparicion[src] = getattr(pkt, 'number', 'N/A')
                    
                    # Si el paquete tiene información Ethernet, asociar MAC con IP
                    if hasattr(pkt, 'eth'):
                        mac = pkt.eth.src
                        if mac not in self.mac_a_ip:
                            self.mac_a_ip[mac] = {
                                'ip': src,
                                'paquete': getattr(pkt, 'number', 'N/A')
                            }
        except:
            pass  # Ignorar errores en este paquete
    
    def obtener_ip_infectada(self):
        """
        Determina la IP infectada (la IP privada más activa).
        
        Returns:
            str: Dirección IP del equipo infectado, o None si no se encontró
        """
        if self.contador_ip:
            return self.contador_ip.most_common(1)[0][0]
        return None
    
    def obtener_mac_infectada(self):
        """
        Obtiene la dirección MAC asociada a la IP infectada.
        
        Returns:
            list: Lista de diccionarios con MAC y paquete
        """
        ip_infectada = self.obtener_ip_infectada()
        if ip_infectada:
            return [
                {'mac': mac, 'paquete': info['paquete']}
                for mac, info in self.mac_a_ip.items() 
                if info['ip'] == ip_infectada
            ]
        return []
    
    def obtener_resultados(self):
        """
        Obtiene los resultados del análisis.
        
        Returns:
            dict: Diccionario con la IP infectada y su MAC
        """
        ip = self.obtener_ip_infectada()
        paquete = self.primera_aparicion.get(ip, 'N/A') if ip else 'N/A'
        
        return {
            'ip_infectada': ip,
            'ip_infectada_paquete': paquete,
            'mac_infectada': self.obtener_mac_infectada()
        }
