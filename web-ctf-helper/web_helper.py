#!/usr/bin/env python3
import argparse
import json
import sys
import re
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

# Desactivar advertencias de SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class WebRecon:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (CTF-Team-Helper)'
        })
        self.results = {
            "target": url,
            "headers": {},
            "technologies": [],
            "forms": [],
            "vulnerabilities": []
        }

    def get_headers(self):
        """Obtiene los headers de la respuesta."""
        try:
            response = self.session.get(self.url, verify=False, timeout=10)
            self.results["headers"] = dict(response.headers)
            
            # Detección básica de tecnologías
            server = response.headers.get('Server', '')
            powered = response.headers.get('X-Powered-By', '')
            if server: self.results["technologies"].append(server)
            if powered: self.results["technologies"].append(powered)
            
            return response.text
        except Exception as e:
            print(f"[-] Error conectando a {self.url}: {e}")
            sys.exit(1)

    def extract_forms(self, html):
        """Extrae formularios y sus inputs."""
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                "action": form.get('action', ''),
                "method": form.get('method', 'GET').upper(),
                "inputs": []
            }
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                form_data["inputs"].append({
                    "name": input_tag.get('name', ''),
                    "type": input_tag.get('type', 'text'),
                    "value": input_tag.get('value', '')
                })
            self.results["forms"].append(form_data)

    def test_sqli(self, url, params):
        """Prueba básica de inyección SQL (Error-based)."""
        payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        # Aquí P2 debe implementar la lógica de inyección
        # Por ahora, solo un placeholder
        pass

    def test_xss(self, url, params):
        """Prueba básica de XSS reflejado."""
        payload = "<script>alert('XSS')</script>"
        # Aquí P2 debe implementar la lógica de inyección
        pass

    def run(self):
        print(f"[*] Iniciando reconocimiento en: {self.url}")
        html = self.get_headers()
        self.extract_forms(html)
        # Aquí se llamarían a test_sqli y test_xss
        print("[+] Reconocimiento completado.")
        return self.results

def main():
    parser = argparse.ArgumentParser(description="Web CTF Helper - Herramienta de reconocimiento web")
    parser.add_argument("--url", required=True, help="URL objetivo (ej: http://target.com)")
    parser.add_argument("--json", action="store_true", help="Exportar resultados en formato JSON")
    parser.add_argument("--output", help="Archivo de salida para guardar el JSON")
    
    args = parser.parse_args()

    scanner = WebRecon(args.url)
    results = scanner.run()

    if args.json or args.output:
        output_data = json.dumps(results, indent=4)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_data)
            print(f"[+] Resultados guardados en {args.output}")
        else:
            print(output_data)

if __name__ == "__main__":
    main()