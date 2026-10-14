#!/usr/bin/env python3
"""
Demo del reporter: genera datos de ejemplo y muestra el reporte bonito.

Uso:
    python3 test_reporter_demo.py
    python3 test_reporter_demo.py --scenario empty
    python3 test_reporter_demo.py --scenario one
    python3 test_reporter_demo.py --scenario full
    python3 test_reporter_demo.py --no-color
    python3 test_reporter_demo.py --width 60
"""
import argparse

from reporter import TerminalReporter


SCENARIO_EMPTY = {
    "target": "https://example.com",
    "security_level": "",
    "technologies": ["Cloudflare"],
    "forms": [],
    "vulnerabilities": [],
    "discovered_urls": [],
}

SCENARIO_ONE = {
    "target": "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit",
    "security_level": "low",
    "technologies": ["Apache/2.4.25 (Debian)", "PHP"],
    "forms": [{"action": "#", "method": "GET",
               "inputs": [{"name": "id", "type": "text"},
                          {"name": "Submit", "type": "submit"}]}],
    "vulnerabilities": [{
        "type": "SQL Injection (error-based)",
        "form_action": "#", "method": "GET", "field": "id",
        "payload": "'",
        "evidence": "you have an error in your sql syntax",
        "severity": "critical", "cvss": 9.8,
    }],
    "discovered_urls": [],
}

SCENARIO_FULL = {
    "target": "http://localhost",
    "security_level": "low",
    "technologies": ["Apache/2.4.25 (Debian)", "PHP", "MySQL"],
    "forms": [
        {"action": "#", "method": "GET",
         "inputs": [{"name": "id", "type": "text"},
                    {"name": "Submit", "type": "submit"}]},
        {"action": "#", "method": "POST",
         "inputs": [{"name": "txtName", "type": "text"},
                    {"name": "mtxMessage", "type": "textarea"},
                    {"name": "btnSign", "type": "submit"}]},
    ],
    "vulnerabilities": [
        {"type": "SQL Injection (error-based)",
         "form_action": "#", "method": "GET", "field": "id",
         "payload": "'",
         "evidence": "you have an error in your sql syntax",
         "severity": "critical", "cvss": 9.8},
        {"type": "SQL Injection (time-based/mysql)",
         "form_action": "#", "method": "GET", "field": "id",
         "payload": "' AND SLEEP(4)#",
         "attempts": 3, "deltas": [0.01, 4.01, 0.02],
         "elapsed_seconds": 4.01, "baseline_seconds": 0.01,
         "severity": "high", "cvss": 8.1},
        {"type": "SQL Injection (boolean-based)",
         "form_action": "#", "method": "GET", "field": "id",
         "payload": "' AND '1'='1' -- ",
         "evidence": "markers: 'user id exists' vs 'user id is missing'",
         "severity": "high", "cvss": 8.1},
        {"type": "XSS (reflected)",
         "location": "URL parameter", "method": "GET", "field": "name",
         "payload": "<script>alert('XSS')</script>",
         "severity": "medium", "cvss": 6.1},
        {"type": "XSS (stored)",
         "location": "form input", "form_action": "", "method": "POST",
         "field": "txtName",
         "payload": "<script>alert('XSS')</script>",
         "severity": "high", "cvss": 7.5},
        {"type": "Local File Inclusion",
         "location": "URL parameter", "method": "GET", "field": "page",
         "payload": "../../../../../etc/passwd",
         "evidence": "/etc/passwd legible",
         "severity": "high", "cvss": 7.5},
        {"type": "Command Injection",
         "form_action": "#", "method": "POST", "field": "ip",
         "payload": "; id",
         "evidence": "uid=33",
         "severity": "critical", "cvss": 9.8},
    ],
    "discovered_urls": [
        "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit",
        "http://localhost/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
        "http://localhost/vulnerabilities/xss_r/?name=test",
        "http://localhost/vulnerabilities/fi/?page=include.php",
        "http://localhost/vulnerabilities/exec/",
    ],
}

SCENARIOS = {"empty": SCENARIO_EMPTY, "one": SCENARIO_ONE, "full": SCENARIO_FULL}


def main():
    parser = argparse.ArgumentParser(description="Demo del reporter")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        default="full")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--width", type=int, default=None)
    args = parser.parse_args()

    reporter = TerminalReporter(
        use_color=False if args.no_color else None,
        width=args.width,
    )
    reporter.print_report(
        SCENARIOS[args.scenario],
        output_path=f"out/{args.scenario}_demo.json",
        elapsed=12.4,
    )


if __name__ == "__main__":
    main()
