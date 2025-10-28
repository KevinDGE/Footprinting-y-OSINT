# footprint_complete 🔎 — README

**Equipo:** Nano  
**Integrantes:** Kevin Grimaldo, Alejandro Martinez, Fernando Garza  
**Materia:** Seguridad Informática / Hacking Ético  
**Fecha:** 23 de octubre de 2025  
**Dominio usado:** `testphp.vulnweb.com` (sitio educativo libre de Acunetix Demo)  
**Permiso:** No se requiere autorización, ya que es un entorno público para pruebas de seguridad. ✅

## Resumen
`footprint_complete.py` es una herramienta en Python para **reconocimiento pasivo** sobre dominios. Por diseño realiza únicamente **acciones pasivas** por defecto (DNS, WHOIS/RDAP, crt.sh, heurísticas de subdominios). El script contiene un **bloque activo** (handshake TLS, fetch HTTP/HTTPS, consultas a Shodan) que **está deshabilitado por defecto** y debe habilitarse explícitamente mediante flags o variables de entorno. Esto reduce el riesgo de realizar operaciones intrusivas sin permiso. 🔒🛡️

## Contenido del repositorio
├─ footprint_complete.py
├─ README.md          
├─ requirements.txt
├─ .gitignore
├─ LICENSE

## Variables de control y mecanismo de autorización 🔧

El mecanismo de control permite habilitar o deshabilitar las acciones activas de forma explícita y segura.

- `AUTHORIZED` — variable en el script (por defecto `False`):
  ```python
  AUTHORIZED = False


**No** cambies a `True` en el código que vas a commitear; usar flags/entorno es más seguro.

* Flags y variables de entorno:

  * `--authorize` (flag CLI) — habilita bloque activo SOLO para la ejecución actual.
  * `--auth-token <token>` (CLI) — token que se compara con `FOOTPRINT_AUTH_TOKEN` en entorno.
  * `FOOTPRINT_AUTHORIZED` (env) — si está `1`, `true` o `yes` habilita el bloque activo.
  * `FOOTPRINT_AUTH_TOKEN` (env) — token secreto esperado por `--auth-token`.
  * `SHODAN_API_KEY` (env) o `--shodan-key` (CLI) — clave para usar Shodan (opcional). **Además** requiere autorización.

> El script imprime en la salida si ejecutó o saltó el bloque activo, y por qué. 📣


## ¿Qué hace por defecto (modo PASIVO)? 🧪

Acciones que se ejecutan sin autorización explícita:

* Consultas DNS: A, AAAA, MX, NS, TXT, CNAME (con timeouts y reintentos).
* WHOIS (python-whois) y fallback a RDAP (`rdap.org`).
* Consulta a `crt.sh` para extraer subdominios desde certificados.
* Heurística de subdominios comunes (www, api, admin, etc.).
* Guarda resultados en `output_passive.json` y `subdomains.csv`.

Estas operaciones son no-intrusivas y están pensadas para minimizar impacto y riesgo. ✅

## Bloque ACTIVO — ¿qué incluye? ⚠️

Acciones que **solo** se ejecutan si autorizas explícitamente:

* Handshake TLS para extraer certificados (`tls_info`).
* Fetch HTTP/HTTPS (cabeceras, robots.txt, sitemaps, parseo de enlaces).
* Búsqueda en Shodan (si se proporciona clave y autorización).

Estas operaciones implican conexiones directas y uso de APIs externas; pueden ser consideradas intrusivas. Ejecuta solo con permiso. 🚨


## Cómo activar el bloque activo (formas seguras) ✅🔐

**Recomendación general:** usa `--authorize` o token temporal; evita cambiar `AUTHORIZED` en el código compartido.

### Opción A — Flag temporal (recomendado)

bash
python3 footprint_complete.py --target example.com --authorize

Activa el bloque activo solo para esa ejecución.

### Opción B — Token temporal (recomendado en entornos compartidos)

1. Exporta token en la sesión (no en el repo):

bash
export FOOTPRINT_AUTH_TOKEN="mi_token_temporal_ABC123"


2. Ejecuta con token:

bash
python3 footprint_complete.py --target example.com --auth-token mi_token_temporal_ABC123


3. Elimina token de la sesión:

bash
unset FOOTPRINT_AUTH_TOKEN


### Opción C — Variable booleana

bash
export FOOTPRINT_AUTHORIZED=1
python3 footprint_complete.py --target example.com
unset FOOTPRINT_AUTHORIZED


### Shodan

Proporciona la clave de Shodan temporalmente:

bash
export SHODAN_API_KEY="tu_clave_shodan"
python3 footprint_complete.py --target example.com --authorize --shodan-key $SHODAN_API_KEY
unset SHODAN_API_KEY

## Checklist de activación segura ☑️

1. Verifica que tienes permiso explícito del propietario del dominio.
2. Prefiere `--authorize` o token temporal en lugar de editar el script.
3. No incluyas claves/tokens en el repositorio (usar `.gitignore`).
4. Revisa la salida del script para confirmar qué se ejecutó.
5. Revoca/`unset` variables de entorno al terminar. 🔁


## Advertencias legales y éticas ⚖️

* Usa este script **solo** sobre dominios que poseas o para los que tengas permiso explícito.
* Aunque `testphp.vulnweb.com` está permitido para pruebas demo, para cualquier otro dominio consigue autorización por escrito.
* Revisa términos de servicio de APIs (p. ej. Shodan) antes de usarlas.
* El equipo no se responsabiliza por el uso indebido de la herramienta. 🚨


## Instalación y dependencias 🧰

Recomendado: crear y activar un virtualenv:

bash
python3 -m venv venv
source venv/bin/activate

Instala dependencias:

bash
pip install -r requirements.txt

## Ejemplos de uso 🧾

* **Modo pasivo (por defecto)**

bash
python3 footprint_complete.py --target testphp.vulnweb.com


* **Modo activo — ejecución puntual**

bash
python3 footprint_complete.py --target testphp.vulnweb.com --authorize --shodan-key YOUR_SHODAN_KEY


* **Modo con token**

bash
export FOOTPRINT_AUTH_TOKEN="temporal"
python3 footprint_complete.py --target testphp.vulnweb.com --auth-token temporal
unset FOOTPRINT_AUTH_TOKEN


## Archivos generados 📤

* `output_passive.json` — reporte completo; incluye `metadata.authorized` indicando si el bloque activo se ejecutó.
* `subdomains.csv` — lista de subdominios detectados con timestamp.

## Mensajes y advertencias en la salida del script 📣

Al iniciar, el script imprime:

* target y timestamp.
* si está en **modo AUTORIZADO** o **NO autorizado**.
* qué módulos/acciones fueron **saltados** por falta de autorización (ej. TLS, HTTP, Shodan).

Ejemplo:

[2025-10-23T12:00:00Z] iniciando recoleccion para: testphp.vulnweb.com
[2025-10-23T12:00:00Z] modo NO autorizado: TLS/HTTP/Shodan serán saltados...
[2025-10-23T12:00:10Z] guardado output_passive.json


## Contribuciones y licencia 🧩

* Contribuciones: abrir issues o pull requests.
* Reglas para cambios que afectan el bloque activo:

  * Deben mantener por defecto el comportamiento **no autorizado**.
  * Documentar cambios en README.
  * Añadir mensajes de advertencia visibles en la salida.
* **Licencia:** MIT (ver `LICENSE`).
