"""
CONFIGURACIÓN DEL ANALIZADOR PCAP
==================================

Este módulo contiene todas las constantes y configuraciones
utilizadas por el analizador de archivos PCAP.
"""

# ====================
# PATRONES SOSPECHOSOS
# ====================

# Patrones de dominios que imitan páginas de autenticación
# Typosquatting = escribir mal un dominio a propósito para engañar
PATRONES_DOMINIO_SOSPECHOSO = [
    'authenticator',        # Palabra clave sospechosa
    'authenticatoor',       # Typosquatting (error intencional)
    'google-authenticator', # Imitación de Google
    'googleauth',           # Variante sospechosa
    'auth-google',          # Otra variante
]

# Lista de dominios legítimos de Google (NO son maliciosos)
DOMINIOS_LEGITIMOS = [
    'google.com',
    'googleapis.com',
    'googleusercontent.com',
    'doubleclick.net',
    'gstatic.com',
    '_googlecast._tcp.local'
]

# ====================
# RANGOS DE RED
# ====================

# Prefijos de direcciones IP privadas (red local)
PREFIJOS_IP_PRIVADA = ('10.', '172.', '192.168.')

# Prefijos de IPs a excluir de detección C2 (privadas y multicast)
PREFIJOS_C2_EXCLUIDOS = ('10.', '172.', '192.168.', '239.', '224.')

# ====================
# PUERTOS SOSPECHOSOS
# ====================

# Puertos comúnmente utilizados por malware y herramientas de ataque
# Formato: {puerto: "descripción del uso malicioso"}
PUERTOS_SOSPECHOSOS = {
    # Puertos de Herramientas de Hacking
    4444: "Metasploit/Meterpreter (puerto por defecto)",
    5555: "Android Debug Bridge (ADB) - Usado en ataques móviles",
    6666: "IRC Backdoor / Varios troyanos",
    6667: "IRC (usado por botnets para C2)",
    6668: "IRC alternativo (botnets)",
    6669: "IRC alternativo (botnets)",
    
    # Puertos de RATs (Remote Access Trojans)
    1234: "Puerto común de RATs genéricos",
    1337: "Puerto 'leet' - Usado por varios backdoors",
    3127: "MyDoom backdoor",
    3128: "Proxy usado por malware / MyDoom",
    5000: "RATs varios / UPnP (explotado)",
    5900: "VNC (usado maliciosamente para control remoto)",
    5901: "VNC alternativo",
    
    # Puertos de Botnets conocidas
    8080: "Proxy HTTP / C2 de varias botnets",
    8443: "HTTPS alternativo / C2 malicioso",
    9001: "Tor (usado para anonimizar C2)",
    9050: "Tor SOCKS proxy",
    9051: "Tor control port",
    
    # Puertos de Cryptominers
    3333: "Stratum mining protocol (cryptominer)",
    14444: "Monero mining pool",
    14433: "Monero mining pool (SSL)",
    
    # Cobalt Strike y otras herramientas APT
    # NOTA: Puertos 443 y 53 excluidos por generar muchos falsos positivos
    50050: "Cobalt Strike (puerto por defecto)",
    
    # Puertos de Windows explotados
    445: "SMB (EternalBlue, WannaCry, etc.)",
    135: "RPC (múltiples exploits)",
    139: "NetBIOS (explotado frecuentemente)",
    
    # Puertos de servicios vulnerables
    3389: "RDP (BlueKeep y otros exploits)",
    22: "SSH (brute force común)",
    23: "Telnet (extremadamente inseguro)",
    21: "FTP (credenciales en texto plano)",
}

# ====================
# DETECCIÓN DE ESCANEO
# ====================

# Número mínimo de puertos diferentes para considerar escaneo
UMBRAL_ESCANEO_PUERTOS = 15

# ====================
# DETECCIÓN DE DESCARGAS
# ====================

# Extensiones de archivos ejecutables o scripts peligrosos
EXTENSIONES_PELIGROSAS = (
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi', '.scr', '.pif', '.jar', '.py', '.sh'
)

# Tipos MIME que indican ejecutables
MIME_TYPES_PELIGROSOS = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-executable',
    'application/x-dosexec',
    'application/vnd.microsoft.portable-executable'
]

# ====================
# DETECCIÓN DE TRANSFERENCIAS
# ====================

# Umbral para considerar una transferencia como "grande" (en bytes)
# 10 MB = 10 * 1024 * 1024 = 10485760 bytes
UMBRAL_TRANSFERENCIA_BYTES = 10 * 1024 * 1024

# ====================
# DETECCIÓN DE ANOMALÍAS ARP
# ====================

# Número de solicitudes ARP para considerar una anomalía (posible escaneo)
UMBRAL_ARP_SOLICITUDES = 50

# ====================
# DETECCIÓN DE LATENCIA
# ====================

# Umbral de RTT (Round Trip Time) en segundos para considerar una conexión lenta
UMBRAL_RTT_LATENCIA = 0.5

# ====================
# DETECCIÓN DE USER-AGENTS
# ====================

# Longitud mínima para un User-Agent válido
UA_MIN_LONGITUD = 5

# ====================
# NOMBRES GENÉRICOS
# ====================

# Nombres de host genéricos a filtrar
HOSTNAMES_GENERICOS = ['WORKGROUP', 'MSHOME']

# Sufijos de nombres de máquina a filtrar
SUFIJO_NOMBRE_MAQUINA = '$'

# ====================
# MAPEO DE VERSIONES DE WINDOWS
# ====================

VERSIONES_WINDOWS = {
    'Windows NT 10.0': ('Windows', '10'),
    'Windows NT 6.3': ('Windows', '8.1'),
    'Windows NT 6.2': ('Windows', '8'),
    'Windows NT 6.1': ('Windows', '7'),
}

# ====================
# CLASIFICACIÓN DE MALWARE
# ====================

# Tipo de malware cuando se detectan dominios falsos de autenticación
TIPO_MALWARE_AUTH_FALSA = "Trojan/Infostealer"
FAMILIA_MALWARE_AUTH_FALSA = "Posible IcedID o similar (Credential Stealer)"

# CWEs relacionados con phishing y robo de credenciales
CWES_ROBO_CREDENCIALES = [
    "CWE-522: Insufficiently Protected Credentials",
    "CWE-1390: Weak Authentication",
    "CWE-346: Origin Validation Error",
    "CWE-601: URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-940: Improper Verification of Source of a Communication Channel"
]

# MITRE ATT&CK Techniques para robo de credenciales
TECNICAS_MITRE_ATTACK = [
    "T1566.002 - Phishing: Spearphishing Link",
    "T1539 - Steal Web Session Cookie",
    "T1056.001 - Input Capture: Keylogging",
    "T1071.001 - Application Layer Protocol: Web Protocols",
    "T1573.001 - Encrypted Channel: Symmetric Cryptography",
    "T1041 - Exfiltration Over C2 Channel"
]

# CVEs potenciales (basado en el tipo de ataque)
CVES_VECTORES_INFECCION_COMUNES = [
    "CVE-2021-40444 - Microsoft MSHTML Remote Code Execution (vector común de infección)",
    "CVE-2022-30190 - Microsoft Windows Support Diagnostic Tool (MSDT) RCE (Follina)"
]

# ====================
# CONFIGURACIÓN DE PYSHARK
# ====================

# Configuración para abrir archivos PCAP
CONFIG_PCAP = {
    'use_json': True,      # Usar formato JSON por compatibilidad
    'keep_packets': False  # No guardar paquetes en memoria (optimización)
}

# ====================
# LÍMITES DE RECURSIÓN
# ====================

# Profundidad máxima para búsquedas recursivas en estructuras anidadas
MAX_PROFUNDIDAD_RECURSION = 10

# ====================
# ARCHIVO A ANALIZAR
# ====================

# Ruta al archivo PCAP que se va a analizar
ARCHIVO_PCAP = "infected.pcap"
