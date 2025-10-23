# Footprinting-y-OSINT
Aprender y automatizar técnicas de footprinting y OSINT en equipo usando herramientas Python (dnspython, python-whois, shodan, python-nmap u otras) para recolectar y correlacionar información pública.

Equipo: Nano
Integrantes: Kevin Grimaldo, Alejandro Martinez, Fernando Garza
Materia: Seguridad Informática / Hacking Ético
Fecha: 23 de octubre de 2025
Dominio usado: testphp.vulnweb.com (sitio educativo libre de Acunetix Demo)
Permiso: No se requiere autorización, ya que es un entorno público para pruebas de seguridad.

🧩 Objetivo

Automatizar la recolección pasiva y activa (protegida) de información pública sobre un dominio, aplicando técnicas de footprinting y OSINT, utilizando Python y librerías de seguridad.

El script recopila información pública (DNS, WHOIS/RDAP, Shodan, certificados TLS, subdominios, headers HTTP) y genera:

Un reporte estructurado en formato JSON (output_passive.json).

Una lista de subdominios en CSV (subdomains.csv).

Soporte opcional para Shodan (requiere API Key).

⚙️ Dependencias

Instala las librerías necesarias:

pip install dnspython requests cryptography python-whois beautifulsoup4


🔐 Opcional: para usar Shodan, instala:

pip install shodan


▶️ Ejecución paso a paso
1️⃣ Modo pasivo (seguro)

Este modo NO interactúa activamente con el objetivo.
Ejecuta:

python3 footprint_complete.py --target testphp.vulnweb.com


Salida esperada en consola:

[2025-10-23T20:30:00Z] iniciando recoleccion pasiva para: testphp.vulnweb.com
[2025-10-23T20:30:10Z] guardado output_passive.json
[2025-10-23T20:30:10Z] guardado subdomains.csv (entradas: X)
[2025-10-23T20:30:10Z] FIN


Archivos generados:

output_passive.json: reporte estructurado con secciones DNS, WHOIS, Shodan, TLS, HTTP.

subdomains.csv: lista con los subdominios encontrados.

🧱 Estructura del JSON generado

El archivo output_passive.json contiene las siguientes secciones:

Sección	Descripción
metadata	Dominio, fecha y nombre del script
dns	Registros A, AAAA, MX, NS, TXT, CNAME
whois	Información WHOIS o fallback RDAP
crtsh	Subdominios extraídos de certificados públicos
subdominios	Lista de subdominios únicos (DNS + crt.sh)
tls	Certificado público del sitio (si está disponible)
http	Headers, robots.txt, sitemap y enlaces detectados
shodan	Información pública de IP si se usa API Key

🧾 Ejemplo de ejecución

Archivo output_passive.json (fragmento):

{
  "metadata": {
    "target": "testphp.vulnweb.com",
    "collected_at": "2025-10-23T20:30:47Z",
    "tool": "footprint_complete.py"
  },
  "dns": {
    "A": ["44.228.249.3"],
    "TXT": ["google-site-verification:toEctYsulNIxgraKk7H3z58PCyz2IOCc36pIupEPmYQ"]
  },
  "http": {
    "status_code": 200,
    "headers": {
      "Server": "nginx/1.19.0",
      "X-Powered-By": "PHP/5.6.40"
    },
    "links_found": ["index.php", "cart.php", "login.php", "guestbook.php"]
  }
}


Archivo subdomains.csv (ejemplo):

subdomain	found_at
testphp.vulnweb.com	2025-10-23T20:30:47Z
www.testphp.vulnweb.com
	2025-10-23T20:30:48Z

✅ Seguridad y ética

El script no ejecuta escaneo activo por defecto.

Solo realiza consultas pasivas permitidas (DNS, WHOIS/RDAP, crt.sh, Shodan, HTTP HEAD/GET).

Cumple las políticas académicas y legales.

Se debe conservar la evidencia de permisos por 12 meses si se habilita el bloque activo.

🧮 Créditos y referencias

Sitio de práctica: http://testphp.vulnweb.com/
 (Acunetix Demo)

Librerías: dnspython, requests, python-whois, cryptography, BeautifulSoup4

API Pública: https://crt.sh, https://rdap.org

Normas éticas: Política de uso responsable y pruebas con consentimiento.
