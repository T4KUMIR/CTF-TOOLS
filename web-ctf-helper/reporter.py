#!/usr/bin/env python3
"""
reporter.py — Reporter de terminal para web_helper.

Convierte el dict de resultados del escáner en salida legible con colores,
tablas y jerarquía visual. Diseñado para que gente sin experiencia en
JSON pueda entender los hallazgos de un vistazo.

Uso:
    from reporter import TerminalReporter
    reporter = TerminalReporter()
    reporter.print_report(results)
"""
import os
import shutil
import sys


# ===================================================================== #
#  Colores ANSI                                                         #
# ===================================================================== #
class Colors:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"

    BLACK    = "\033[30m"
    RED      = "\033[31m"
    GREEN    = "\033[32m"
    YELLOW   = "\033[33m"
    BLUE     = "\033[34m"
    MAGENTA  = "\033[35m"
    CYAN     = "\033[36m"
    WHITE    = "\033[37m"

    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW= "\033[43m"

    @classmethod
    def disable(cls):
        """Desactiva todos los colores (para --no-color)."""
        for attr in dir(cls):
            if not attr.startswith("_") and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")
        # Recalcular el mapa de colores para reflejar el cambio de estado.
        globals()["SEVERITY_COLOR"] = {
            "critical": Colors.RED,
            "high": Colors.YELLOW,
            "medium": Colors.CYAN,
            "low": Colors.GREEN,
            "info": Colors.DIM,
        }


# ===================================================================== #
#  Iconos y etiquetas por severidad                                    #
# ===================================================================== #
SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}

SEVERITY_COLOR = {
    "critical": Colors.RED,
    "high":     Colors.YELLOW,
    "medium":   Colors.CYAN,
    "low":      Colors.GREEN,
    "info":     Colors.DIM,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ===================================================================== #
#  Reporter                                                            #
# ===================================================================== #
class TerminalReporter:
    def __init__(self, use_color=None, width=None, show_discovered=True):
        """
        use_color: None = autodetecta, True/False = fuerza
        width: ancho de las cajas (default: min(terminal_width, 78))
        show_discovered: mostrar URLs descubiertas por el crawler
        """
        if use_color is None:
            use_color = self._auto_color()
        if not use_color:
            Colors.disable()

        term_w = shutil.get_terminal_size((80, 24)).columns
        self.width = width or min(term_w - 2, 78)
        self.show_discovered = show_discovered

    @staticmethod
    def _auto_color():
        """Detecta si la terminal soporta color."""
        if os.environ.get("NO_COLOR"):
            return False
        if not sys.stdout.isatty():
            return False
        if os.environ.get("TERM") in (None, "", "dumb"):
            return False
        return True

    # ------------------------------------------------------------------ #
    #  Helpers de dibujo                                                 #
    # ------------------------------------------------------------------ #
    def _box_top(self, char="═"):
        print(f"╔{char * (self.width - 2)}╗")

    def _box_bottom(self, char="═"):
        print(f"╚{char * (self.width - 2)}╝")

    def _box_line(self, text="", align="center"):
        inner = self.width - 4
        if align == "center":
            line = text.center(inner)
        elif align == "left":
            line = " " + text.ljust(inner - 1)
        else:
            line = text.rjust(inner - 1) + " "
        print(f"║ {line} ║")

    def _sep(self, char="─"):
        print(f"{Colors.DIM}{char * self.width}{Colors.RESET}")

    def _header(self, text, icon="📊"):
        self._sep()
        print(f"{Colors.BOLD}{icon}  {text.upper()}{Colors.RESET}")
        self._sep()

    # ------------------------------------------------------------------ #
    #  Reporte principal                                                 #
    # ------------------------------------------------------------------ #
    def print_report(self, results, output_path=None, elapsed=None):
        self._print_banner()
        self._print_target_info(results, elapsed)
        self._print_summary(results)
        self._print_vulnerabilities(results)
        if self.show_discovered and results.get("discovered_urls"):
            self._print_discovered(results)
        if output_path:
            self._print_output_path(output_path)
        self._print_footer()

    # ------------------------------------------------------------------ #
    def _print_banner(self):
        print()
        self._box_top()
        self._box_line("WEB CTF HELPER — RESULTADOS DE ESCANEO")
        self._box_bottom()
        print()

    # ------------------------------------------------------------------ #
    def _print_target_info(self, results, elapsed):
        target = results.get("target", "?")
        sec = results.get("security_level", "")
        techs = results.get("technologies", [])

        print(f"  {Colors.BOLD}🎯 Target:{Colors.RESET}    {target}")
        if sec:
            print(f"  {Colors.BOLD}⚙️  Security:{Colors.RESET}  {sec}")
        if techs:
            print(f"  {Colors.BOLD}🌐 Tech:{Colors.RESET}      "
                  f"{', '.join(techs[:5])}")
        if elapsed is not None:
            print(f"  {Colors.BOLD}⏱️  Tiempo:{Colors.RESET}    {elapsed:.1f}s")
        print()

    # ------------------------------------------------------------------ #
    def _print_summary(self, results):
        vulns = results.get("vulnerabilities", [])
        forms = results.get("forms", [])

        self._header("Resumen", "📈")

        counts = {s: 0 for s in SEVERITY_ORDER}
        for v in vulns:
            sev = v.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        total = len(vulns)
        print(f"     Formularios detectados ... {len(forms)}")
        print(f"     Vulnerabilidades ........ {self._colored_total(total)}")
        print()

        for sev in SEVERITY_ORDER:
            c = counts.get(sev, 0)
            if c == 0 and sev == "info":
                continue
            icon = SEVERITY_ICON.get(sev, "?")
            color = SEVERITY_COLOR.get(sev, "")
            bar = "█" * min(c * 2, 30)
            dots = "░" * (30 - len(bar))
            label = sev.capitalize().ljust(9)
            print(f"     {icon} {color}{label}{Colors.RESET} "
                  f"{color}{bar}{Colors.RESET}{Colors.DIM}{dots}{Colors.RESET} "
                  f"{color}{c}{Colors.RESET}")
        print()

    def _colored_total(self, n):
        if n == 0:
            return f"{Colors.GREEN}{n}{Colors.RESET}"
        if n <= 2:
            return f"{Colors.YELLOW}{n}{Colors.RESET}"
        return f"{Colors.RED}{Colors.BOLD}{n}{Colors.RESET}"

    # ------------------------------------------------------------------ #
    def _print_vulnerabilities(self, results):
        vulns = results.get("vulnerabilities", [])
        if not vulns:
            self._header("Hallazgos", "🔍")
            print(f"     {Colors.GREEN}✓ "
                  f"No se detectaron vulnerabilidades{Colors.RESET}")
            print()
            return

        def sort_key(v):
            sev = v.get("severity", "info").lower()
            idx = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99
            return (idx, v.get("type", ""))

        vulns_sorted = sorted(vulns, key=sort_key)

        self._header(f"Hallazgos ({len(vulns)})", "🔍")

        for i, v in enumerate(vulns_sorted, 1):
            self._print_one_vuln(i, v)
        print()

    def _print_one_vuln(self, idx, v):
        sev = v.get("severity", "info").lower()
        icon = SEVERITY_ICON.get(sev, "?")
        color = SEVERITY_COLOR.get(sev, "")
        vtype = v.get("type", "Unknown")

        print(f"  {Colors.BOLD}[{idx}]{Colors.RESET} "
              f"{icon} {color}{Colors.BOLD}{sev.upper()}{Colors.RESET}"
              f" — {Colors.BOLD}{vtype}{Colors.RESET}")

        fields = []
        if "field" in v:
            fields.append(("Campo", v["field"]))
        if "location" in v:
            fields.append(("Ubicación", v["location"]))
        if "method" in v:
            fields.append(("Método", v["method"]))
        if "form_action" in v:
            fields.append(("Form action", v["form_action"]))
        if "payload" in v:
            fields.append(("Payload", v["payload"]))
        if "evidence" in v:
            fields.append(("Evidencia", v["evidence"]))
        if "elapsed_seconds" in v:
            delta = ""
            if "baseline_seconds" in v:
                delta = (f" (baseline {v['baseline_seconds']}s)")
            fields.append(("Tiempo", f"{v['elapsed_seconds']}s{delta}"))
        if "cvss" in v:
            fields.append(("CVSS", str(v["cvss"])))

        for j, (label, value) in enumerate(fields):
            is_last = (j == len(fields) - 1)
            branch = "└─" if is_last else "├─"
            print(f"       {Colors.DIM}{branch}{Colors.RESET} "
                  f"{label.ljust(13)} "
                  f"{Colors.DIM}{value}{Colors.RESET}")
        print()

    # ------------------------------------------------------------------ #
    def _print_discovered(self, results):
        urls = results.get("discovered_urls", [])
        if not urls:
            return
        self._header(f"URLs descubiertas ({len(urls)})", "🕷️")
        for u in urls[:20]:
            print(f"     {Colors.CYAN}•{Colors.RESET} {u}")
        if len(urls) > 20:
            print(f"     {Colors.DIM}... y {len(urls) - 20} más{Colors.RESET}")
        print()

    # ------------------------------------------------------------------ #
    def _print_output_path(self, path):
        self._sep()
        print(f"  {Colors.BOLD}💾 Guardado en:{Colors.RESET} {path}")
        self._sep()
        print()

    def _print_footer(self):
        print(f"  {Colors.YELLOW}⚠️  Solo escanea objetivos para los que "
              f"tengas autorización.{Colors.RESET}")
        print()
