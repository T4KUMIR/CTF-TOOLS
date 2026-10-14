#!/usr/bin/env python3
"""
Tests unitarios para web_helper.py (Fase 1 — versión generalizada).

Ejecución:
    python3 -m unittest -v test_web_helper
"""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from web_helper import WebRecon, SEVERITY_MAP


class XssTests(unittest.TestCase):
    """XSS: el tipo y la severidad dependen del módulo."""

    def _scan_xss(self, module):
        scanner = WebRecon(f"http://example.test/vulnerabilities/{module}/")
        scanner.results["forms"] = [{
            "action": f"http://example.test/vulnerabilities/{module}/",
            "method": "POST",
            "inputs": [{"name": "name", "type": "text"}],
        }]
        scanner._submit_form_payload = lambda *args, **kw: SimpleNamespace(
            text="<script>alert('XSS')</script>"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            scanner.test_xss()
        return scanner.results["vulnerabilities"][0]

    def test_xss_reflected_in_xss_r(self):
        vuln = self._scan_xss("xss_r")
        self.assertEqual(vuln["type"], "XSS (reflected)")
        self.assertEqual(vuln["severity"], "medium")
        self.assertEqual(vuln["cvss"], 6.1)

    def test_xss_stored_in_xss_s(self):
        vuln = self._scan_xss("xss_s")
        self.assertEqual(vuln["type"], "XSS (stored)")
        self.assertEqual(vuln["severity"], "high")
        self.assertEqual(vuln["cvss"], 7.5)


class SqliTimeTests(unittest.TestCase):
    """SQLi time-based: baseline con '1', corre en todos los campos."""

    def test_time_based_runs_on_all_fields(self):
        scanner = WebRecon("http://example.test/vulnerabilities/sqli/")
        scanner.results["forms"] = [{
            "action": "http://example.test/vulnerabilities/sqli/",
            "method": "POST",
            "inputs": [{"name": "id", "type": "text"}],
        }]
        # Ya hay un error-based detectado en este campo → debe seguir probando
        scanner.results["vulnerabilities"] = [{
            "type": "SQL Injection (error-based)",
            "form_action": "http://example.test/vulnerabilities/sqli/",
            "field": "id",
        }]
        submitted = []
        scanner._submit_form_payload = lambda *args, **kw: (
            submitted.append(args) or SimpleNamespace(status_code=200)
        )

        with contextlib.redirect_stdout(io.StringIO()):
            scanner.test_sqli_time(delay=1, threshold=100)

        self.assertTrue(submitted, "Debe haber enviado al menos un payload")
        # Todos los envíos van al campo 'id'
        self.assertTrue(all(call[1] == "id" for call in submitted))
        # Baseline usa '1' (no '' — cambio de Fase 1)
        self.assertTrue(
            any(call[2] == "1" for call in submitted),
            f"Ningún envío con baseline '1'. Payloads vistos: "
            f"{[call[2] for call in submitted]}",
        )
        # Al menos un payload termina con '#' (comentario MySQL)
        self.assertTrue(
            any(call[2].endswith("#") for call in submitted),
            f"Ningún payload con '#'. Payloads: {[call[2] for call in submitted]}",
        )


class SqliHighPopupTests(unittest.TestCase):
    """DVWA high: el flujo del popup solo se activa con security=high."""

    def test_high_sqli_creates_virtual_form_from_module(self):
        """
        Cuando security=high y estamos en /sqli sin <form> en el HTML,
        extract_forms debe crear un formulario virtual apuntando a
        session-input.php.
        """
        scanner = WebRecon(
            "http://example.test/vulnerabilities/sqli/?id=1&Submit=Submit",
            security="high",
        )
        # HTML sin <form>, solo texto
        scanner.extract_forms("<html><body>No form here</body></html>")

        self.assertEqual(len(scanner.results["forms"]), 1)
        form = scanner.results["forms"][0]
        self.assertEqual(
            form["action"],
            "http://example.test/vulnerabilities/sqli/session-input.php",
        )
        self.assertEqual(form["method"], "POST")
        # Solo método declarado (no alternativo) para popups
        self.assertEqual(list(scanner._form_methods(form)), ["POST"])

    def test_high_sqli_submits_to_popup_then_loads_module(self):
        """
        _submit_form_payload, en high+popup, debe:
          1) POST al popup con el payload.
          2) GET al módulo para ejecutar la query vulnerable.
        """
        scanner = WebRecon(
            "http://example.test/vulnerabilities/sqli/?id=1&Submit=Submit",
            security="high",
        )
        scanner.extract_forms("<html></html>")
        form = scanner.results["forms"][0]

        popup_response = SimpleNamespace(status_code=200)
        module_response = SimpleNamespace(status_code=200, text="SQL error")
        scanner.session.post = Mock(return_value=popup_response)
        scanner.session.get = Mock(return_value=module_response)

        response = scanner._submit_form_payload(
            form, "id", "' AND SLEEP(3)-- -", "POST"
        )

        # El response final es el del módulo (donde vive la query)
        self.assertIs(response, module_response)

        # POST al popup con payload + Submit
        scanner.session.post.assert_called_once()
        call_args, call_kwargs = scanner.session.post.call_args
        self.assertIn("session-input.php", call_args[0])
        self.assertEqual(
            call_kwargs["data"],
            {"id": "1' AND SLEEP(3)-- -", "Submit": "Submit"},
        )

        # GET al módulo para ejecutar la query vulnerable
        scanner.session.get.assert_called_once_with(
            scanner.url, verify=False, timeout=15
        )


class LoginTests(unittest.TestCase):
    """Login genérico: detección de form con input[type=password]."""

    def test_login_detects_form_and_fills_credentials(self):
        scanner = WebRecon("http://example.test/")
        html = """
        <html><body>
          <form action="/auth" method="POST">
            <input type="text" name="username">
            <input type="password" name="pass">
            <input type="hidden" name="csrf" value="tok123">
            <input type="submit" name="submit" value="Login">
          </form>
        </body></html>
        """
        scanner.session.get = Mock(return_value=SimpleNamespace(
            text=html, status_code=200
        ))
        # Respuesta tras login: ya no hay password field
        scanner.session.post = Mock(return_value=SimpleNamespace(
            text="<html>Welcome admin</html>", status_code=200
        ))

        result = scanner.login("admin", "secret")
        self.assertTrue(result)

        # Verificar el POST con credenciales + hidden
        scanner.session.post.assert_called_once()
        call_args, call_kwargs = scanner.session.post.call_args
        self.assertIn("/auth", call_args[0])
        self.assertEqual(call_kwargs["data"]["username"], "admin")
        self.assertEqual(call_kwargs["data"]["pass"], "secret")
        self.assertEqual(call_kwargs["data"]["csrf"], "tok123")

    def test_login_returns_false_when_no_password_field(self):
        scanner = WebRecon("http://example.test/")
        scanner.session.get = Mock(return_value=SimpleNamespace(
            text="<html>Sin form de login</html>", status_code=200
        ))
        result = scanner.login("admin", "secret")
        self.assertFalse(result)

    def test_login_returns_false_when_still_shows_password_after_post(self):
        scanner = WebRecon("http://example.test/")
        html_login = """
        <form action="/auth" method="POST">
          <input type="text" name="username">
          <input type="password" name="pass">
        </form>
        """
        scanner.session.get = Mock(return_value=SimpleNamespace(
            text=html_login, status_code=200
        ))
        # El POST devuelve el mismo form (login fallido)
        scanner.session.post = Mock(return_value=SimpleNamespace(
            text=html_login, status_code=200
        ))
        result = scanner.login("admin", "wrong")
        self.assertFalse(result)


class SeverityMapTests(unittest.TestCase):
    """Todos los tipos de vuln deben tener severity/cvss."""

    def test_all_vuln_types_have_severity(self):
        expected_types = [
            "SQL Injection (error-based)",
            "SQL Injection (time-based/mysql)",
            "SQL Injection (boolean-based)",
            "XSS (reflected)",
            "XSS (stored)",
            "Local File Inclusion",
            "Command Injection",
        ]
        for vtype in expected_types:
            with self.subTest(vtype=vtype):
                self.assertIn(vtype, SEVERITY_MAP)
                sev, cvss = SEVERITY_MAP[vtype]
                self.assertIn(sev, ("low", "medium", "high", "critical"))
                self.assertGreater(cvss, 0.0)

    def test_dedupe_enriches_with_severity_and_cvss(self):
        vulns = []
        WebRecon._dedupe(
            vulns,
            {"type": "SQL Injection (error-based)", "field": "id"},
            ("type", "field"),
        )
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["severity"], "critical")
        self.assertEqual(vulns[0]["cvss"], 9.8)

    def test_dedupe_does_not_add_duplicates(self):
        vulns = []
        WebRecon._dedupe(
            vulns,
            {"type": "XSS (reflected)", "location": "URL parameter", "field": "q"},
            ("type", "location", "field"),
        )
        WebRecon._dedupe(
            vulns,
            {"type": "XSS (reflected)", "location": "URL parameter", "field": "q"},
            ("type", "location", "field"),
        )
        self.assertEqual(len(vulns), 1)


if __name__ == "__main__":
    unittest.main()