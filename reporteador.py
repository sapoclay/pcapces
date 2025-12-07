"""
GENERADOR DE REPORTES
======================

Este módulo genera reportes formateados con colores bonicos 
para presentar los resultados del análisis de malware de manera clara.
"""

from colorama import Fore, Style


class Reporteador:
    """
    Genera reportes formateados de los resultados del análisis.
    """
    
    def __init__(self):
        """Inicializa el generador de reportes."""
        pass
    
    def generar_reporte_completo(self, resultados_analisis, clasificacion):
        """
        Genera el reporte completo con todos los hallazgos.
        
        Args:
            resultados_analisis: Diccionario con resultados del análisis
            clasificacion: Diccionario con la clasificación del malware
        """
        self._imprimir_reporte_cliente_infectado(resultados_analisis)
        self._imprimir_reporte_clasificacion(resultados_analisis, clasificacion)
        self._imprimir_resumen_amenazas(resultados_analisis)
    
    def _imprimir_reporte_cliente_infectado(self, resultados):
        """
        Imprime el reporte del cliente Windows infectado.
        
        Args:
            resultados: Diccionario con resultados del análisis
        """
        print("=" * 80)
        print(f"{Fore.BLUE}{Style.BRIGHT}ANÁLISIS DEL CLIENTE WINDOWS INFECTADO{Style.RESET_ALL}")
        print("=" * 80)
        print()
        
        # 1. Dirección IP
        print(f"{Fore.CYAN}1. ¿Cuál es la dirección IP del cliente Windows infectado?{Style.RESET_ALL}")
        ip = resultados.get('ip_infectada', 'No encontrado')
        paquete = resultados.get('ip_infectada_paquete', 'N/A')
        print(f"   {Fore.GREEN}Respuesta: {Fore.YELLOW}{ip} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        print()
        
        # 2. Dirección MAC
        print(f"{Fore.CYAN}2. ¿Cuál es la dirección MAC del cliente Windows infectado?{Style.RESET_ALL}")
        if resultados.get('mac_infectada'):
            for item in resultados['mac_infectada']:
                mac = item['mac']
                paquete = item['paquete']
                print(f"   {Fore.GREEN}Respuesta: {Fore.YELLOW}{mac} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}Respuesta: No encontrado{Style.RESET_ALL}")
        print()
        
        # 3. Nombre de host
        print(f"{Fore.CYAN}3. ¿Cuál es el nombre de host del cliente Windows infectado?{Style.RESET_ALL}")
        if resultados.get('hostnames'):
            for item in resultados['hostnames']:
                nombre = item['nombre']
                paquete = item['paquete']
                print(f"   {Fore.GREEN}Respuesta: {Fore.YELLOW}{nombre} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}Respuesta: No encontrado{Style.RESET_ALL}")
        print()
        
        # 4. Nombre de cuenta de usuario
        print(f"{Fore.CYAN}4. ¿Cuál es el nombre de cuenta de usuario del cliente Windows infectado?{Style.RESET_ALL}")
        if resultados.get('usuarios'):
            for item in resultados['usuarios']:
                nombre = item['nombre']
                paquete = item['paquete']
                print(f"   {Fore.GREEN}Respuesta: {Fore.YELLOW}{nombre} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}Respuesta: No encontrado{Style.RESET_ALL}")
        print()
        
        # 5. Dominio falso de Google Authenticator
        print(f"{Fore.CYAN}5. ¿Cuál es el nombre de dominio probable de la página falsa de Google Authenticator?{Style.RESET_ALL}")
        if resultados.get('dominios_auth_falsos'):
            for item in resultados['dominios_auth_falsos']:
                dominio = item['dominio']
                paquete = item['paquete']
                print(f"   {Fore.GREEN}Respuesta: {Fore.RED}{dominio} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}Respuesta: No encontrado{Style.RESET_ALL}")
        print()
        
        # 6. Servidores C2
        print(f"{Fore.CYAN}6. ¿Cuáles son las direcciones IP utilizadas para los servidores C2 de esta infección?{Style.RESET_ALL}")
        if resultados.get('ips_c2'):
            for item in resultados['ips_c2']:
                ip = item['ip']
                paquete = item['paquete']
                print(f"   {Fore.GREEN}Respuesta: {Fore.RED}{ip} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}Respuesta: No encontrado{Style.RESET_ALL}")
        print()
    
    def _imprimir_reporte_clasificacion(self, resultados, clasificacion):
        """
        Imprime el reporte de clasificación de malware.
        
        Args:
            resultados: Diccionario con resultados del análisis
            clasificacion: Diccionario con la clasificación del malware
        """
        print("=" * 80)
        print(f"{Fore.BLUE}{Style.BRIGHT}CLASIFICACIÓN DE MALWARE Y ANÁLISIS DE SEGURIDAD{Style.RESET_ALL}")
        print("=" * 80)
        print()
        
        # 7. Tipo de malware
        print(f"{Fore.CYAN}7. ¿Qué tipo de malware es?{Style.RESET_ALL}")
        print(f"   {Fore.MAGENTA}Tipo: {clasificacion['tipo']}{Style.RESET_ALL}")
        print(f"   {Fore.MAGENTA}Familia: {clasificacion['familia']}{Style.RESET_ALL}")
        print()
        
        # 8. CVEs relacionados
        print(f"{Fore.CYAN}8. ¿Qué CVEs (Common Vulnerabilities and Exposures) están relacionados?{Style.RESET_ALL}")
        if clasificacion['cves']:
            for cve in clasificacion['cves']:
                print(f"   {Fore.RED}- {cve}{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}- No se identificaron CVEs específicos{Style.RESET_ALL}")
        print()
        
        # 9. CWEs asociados
        print(f"{Fore.CYAN}9. ¿Qué CWEs (Common Weakness Enumeration) están asociados?{Style.RESET_ALL}")
        if clasificacion['cwes']:
            for cwe in clasificacion['cwes']:
                print(f"   {Fore.YELLOW}- {cwe}{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}- No se identificaron CWEs{Style.RESET_ALL}")
        print()
        
        # 10. Técnicas MITRE ATT&CK
        print(f"{Fore.CYAN}10. ¿Qué técnicas MITRE ATT&CK utiliza el malware?{Style.RESET_ALL}")
        if clasificacion['mitre_attack']:
            for tecnica in clasificacion['mitre_attack']:
                print(f"   {Fore.MAGENTA}- {tecnica}{Style.RESET_ALL}")
        else:
            print(f"   {Fore.YELLOW}- No se identificaron técnicas MITRE ATT&CK{Style.RESET_ALL}")
        print()
        
        # 11. CPEs del sistema infectado
        print(f"{Fore.CYAN}11. ¿Qué CPEs (Common Platform Enumeration) tiene el sistema infectado?{Style.RESET_ALL}")
        if resultados.get('cpes'):
            for entrada_cpe in resultados['cpes']:
                print(f"   {Fore.GREEN}Tipo: {Fore.YELLOW}{entrada_cpe['tipo']}{Style.RESET_ALL}")
                print(f"   {Fore.GREEN}CPE: {Fore.YELLOW}{entrada_cpe['cpe']}{Style.RESET_ALL}")
                print(f"   {Fore.GREEN}Descripción: {Fore.YELLOW}{entrada_cpe['descripcion']}{Style.RESET_ALL}")
                print()
        else:
            print(f"   {Fore.YELLOW}- No se pudieron determinar CPEs{Style.RESET_ALL}")
            print()
    
    def _imprimir_resumen_amenazas(self, resultados):
        """
        Imprime un resumen de las amenazas detectadas.
        
        Args:
            resultados: Diccionario con resultados del análisis
        """
        print("=" * 80)
        print(f"{Fore.BLUE}{Style.BRIGHT}RESUMEN DE AMENAZAS DETECTADAS{Style.RESET_ALL}")
        print("=" * 80)
        print()
        
        # Dominios maliciosos
        print(f"{Fore.CYAN}🔗 Dominios maliciosos:{Style.RESET_ALL}")
        if resultados.get('dominios_auth_falsos'):
            for item in resultados['dominios_auth_falsos']:
                dominio = item['dominio']
                paquete = item['paquete']
                print(f"  {Fore.RED}⚠ {dominio} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguno detectado{Style.RESET_ALL}")
        print()
        
        # IPs de servidores C2
        print(f"{Fore.CYAN}🎯 IPs de servidores C2:{Style.RESET_ALL}")
        if resultados.get('ips_c2'):
            for item in resultados['ips_c2']:
                ip = item['ip']
                paquete = item['paquete']
                print(f"  {Fore.RED}⚠ {ip} {Fore.WHITE}[Paquete #{paquete}]{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguno detectado{Style.RESET_ALL}")
        print()
        
        # Conexiones a puertos sospechosos
        print(f"{Fore.CYAN}🚪 Conexiones a puertos sospechosos:{Style.RESET_ALL}")
        if resultados.get('conexiones_puertos_sospechosos'):
            for conn in resultados['conexiones_puertos_sospechosos']:
                print(f"  {Fore.RED}⚠ {conn['ip']}:{conn['puerto']} ({conn['protocolo']}) {Fore.WHITE}[Paquete #{conn['paquete']}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ {conn['descripcion']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()
        
        # Escaneos de puertos
        print(f"{Fore.CYAN}🔍 Escaneos de puertos detectados:{Style.RESET_ALL}")
        if resultados.get('escaneos_puertos'):
            for escaneo in resultados['escaneos_puertos']:
                severidad_color = Fore.RED if escaneo['severidad'] == 'ALTA' else (
                    Fore.YELLOW if escaneo['severidad'] == 'MEDIA' else Fore.WHITE
                )
                print(f"  {severidad_color}⚠ [{escaneo['severidad']}] {escaneo['ip_origen']} → {escaneo['ip_destino']} {Fore.WHITE}[Inicio: Paquete #{escaneo.get('paquete_inicio', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ Tipo: {escaneo['tipo_escaneo']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ Puertos escaneados: {escaneo['puertos_escaneados']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ Muestra: {escaneo['muestra_puertos']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguno detectado{Style.RESET_ALL}")
        print()
        
        # Descargas sospechosas
        print(f"{Fore.CYAN}📥 Descargas sospechosas:{Style.RESET_ALL}")
        if resultados.get('descargas_sospechosas'):
            for descarga in resultados['descargas_sospechosas']:
                print(f"  {Fore.RED}⚠ {descarga['archivo']} ({descarga['protocolo']}) {Fore.WHITE}[Paquete #{descarga.get('paquete', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ Origen: {descarga['origen']} → Destino: {descarga['destino']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ Info: {descarga['info']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()
        
        # Transferencias grandes
        print(f"{Fore.CYAN}📡 Transferencias de datos grandes:{Style.RESET_ALL}")
        if resultados.get('transferencias_grandes'):
            for transf in resultados['transferencias_grandes']:
                print(f"  {Fore.MAGENTA}⚠ {transf['megabytes']} MB - {transf['tipo']} {Fore.WHITE}[Inicio: Paquete #{transf.get('paquete_inicio', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ {transf['origen']} → {transf['destino']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()
        
        # Credenciales expuestas
        print(f"{Fore.CYAN}🔑 Credenciales expuestas (Texto Plano):{Style.RESET_ALL}")
        if resultados.get('credenciales_expuestas'):
            for cred in resultados['credenciales_expuestas']:
                print(f"  {Fore.RED}⚠ Protocolo: {cred['protocolo']} {Fore.WHITE}[Paquete #{cred.get('paquete', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ Info: {cred['info']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ {cred['origen']} → {cred['destino']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()

        # User-Agents anómalos
        print(f"{Fore.CYAN}🎭 User-Agents anómalos:{Style.RESET_ALL}")
        if resultados.get('user_agents_anomalos'):
            for ua in resultados['user_agents_anomalos']:
                print(f"  {Fore.MAGENTA}⚠ {ua['motivo']} {Fore.WHITE}[Paquete #{ua.get('paquete', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ UA: {ua['ua']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguno detectado{Style.RESET_ALL}")
        print()

        # Anomalías ARP
        print(f"{Fore.CYAN}📢 Anomalías ARP:{Style.RESET_ALL}")
        if resultados.get('anomalias_arp'):
            for arp in resultados['anomalias_arp']:
                print(f"  {Fore.RED}⚠ {arp['tipo']} {Fore.WHITE}[Inicio: Paquete #{arp.get('paquete_inicio', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ {arp['detalle']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()

        # Conexiones lentas (RTT)
        print(f"{Fore.CYAN}🐢 Conexiones lentas (Alta Latencia RTT):{Style.RESET_ALL}")
        if resultados.get('conexiones_lentas'):
            for conn in resultados['conexiones_lentas']:
                print(f"  {Fore.YELLOW}⚠ {conn['rtt']:.4f}s - {conn['origen']} → {conn['destino']}:{conn['puerto']} {Fore.WHITE}[Paquete #{conn.get('paquete', 'N/A')}]{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguna detectada{Style.RESET_ALL}")
        print()

        # Errores HTTP
        print(f"{Fore.CYAN}❌ Respuestas HTTP de Error (4xx/5xx):{Style.RESET_ALL}")
        if resultados.get('errores_http'):
            for err in resultados['errores_http']:
                print(f"  {Fore.RED}⚠ HTTP {err['codigo']} - {err['descripcion']} (x{err['conteo']}) {Fore.WHITE}[Inicio: Paquete #{err.get('paquete', 'N/A')}]{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ Servidor: {err['servidor']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}├─ URI: {err['uri']}{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}└─ {err['origen']} → {err['destino']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Ninguno detectado{Style.RESET_ALL}")
        print()
        
        # Resumen estadístico
        print("=" * 80)
        print(f"{Fore.BLUE}{Style.BRIGHT}ESTADÍSTICAS DE AMENAZAS{Style.RESET_ALL}")
        print("=" * 80)
        total_amenazas = (
            len(resultados.get('dominios_auth_falsos', [])) +
            len(resultados.get('ips_c2', [])) +
            len(resultados.get('conexiones_puertos_sospechosos', [])) +
            len(resultados.get('escaneos_puertos', [])) +
            len(resultados.get('descargas_sospechosas', [])) +
            len(resultados.get('transferencias_grandes', [])) +
            len(resultados.get('credenciales_expuestas', [])) +
            len(resultados.get('user_agents_anomalos', [])) +
            len(resultados.get('anomalias_arp', [])) +
            len(resultados.get('errores_http', []))
        )
        
        if total_amenazas > 0:
            print(f"  {Fore.RED}Total de indicadores de amenaza: {total_amenazas}{Style.RESET_ALL}")
            print(f"    • Dominios maliciosos: {len(resultados.get('dominios_auth_falsos', []))}")
            print(f"    • Servidores C2: {len(resultados.get('ips_c2', []))}")
            print(f"    • Puertos sospechosos: {len(resultados.get('conexiones_puertos_sospechosos', []))}")
            print(f"    • Escaneos de puertos: {len(resultados.get('escaneos_puertos', []))}")
            print(f"    • Descargas sospechosas: {len(resultados.get('descargas_sospechosas', []))}")
            print(f"    • Transferencias grandes: {len(resultados.get('transferencias_grandes', []))}")
            print(f"    • Credenciales expuestas: {len(resultados.get('credenciales_expuestas', []))}")
            print(f"    • User-Agents anómalos: {len(resultados.get('user_agents_anomalos', []))}")
            print(f"    • Anomalías ARP: {len(resultados.get('anomalias_arp', []))}")
            print(f"    • Errores HTTP: {len(resultados.get('errores_http', []))}")
        else:
            print(f"  {Fore.GREEN}No se detectaron amenazas significativas.{Style.RESET_ALL}")
        print()
        
        print("=" * 80)

