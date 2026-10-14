# 🌐 Web CTF Helper

Web CTF Helper es una herramienta de reconocimiento y explotación web diseñada para asistir en competencias de CTF y laboratorios de seguridad. Permite detectar vulnerabilidades comunes de forma automatizada y presentar los resultados de manera legible.

## ✨ Características

- **Detección de Vulnerabilidades**:
  - **SQL Injection**: Error-based, Time-based (MySQL, Postgres, MSSQL) y Boolean-based.
  - **XSS**: Reflected y Stored.
  - **LFI**: Local File Inclusion.
  - **Command Injection**: Ejecución de comandos en el sistema.
- **Reconocimiento**:
  - Crawler básico integrado para descubrir endpoints con parámetros.
  - Detección de tecnologías web (CMS, Servidores, Lenguajes).
- **Automatización**:
  - Login genérico automático.
  - Modo optimizado para DVWA (Damn Vulnerable Web App).
- **Reportero Visual**:
  - Salida formateada en terminal con colores, iconos de severidad y jerarquía visual para facilitar el análisis.
  - Exportación a formato JSON para integración con otras herramientas.

## 🚀 Instalación

1. Clona el repositorio o descarga los archivos.
2. Crea un entorno virtual (opcional pero recomendado):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Uso

### Escaneo Básico
```bash
python3 web_helper.py --url https://target.com
```

### Escaneo con Login
```bash
python3 web_helper.py --url https://target.com --login-user admin --login-pass password
```

### Modo DVWA (Laboratorios)
```bash
python3 web_helper.py --url http://localhost --dvwa --security low
```

### Escaneo Exhaustivo con Crawler
```bash
python3 web_helper.py --url https://target.com --crawl --depth 2
```

### Opciones de Salida
- `--json`: Imprime los resultados en formato JSON puro.
- `--no-color`: Desactiva los colores en el reporte visual.
- `--output archivo.json`: Guarda los resultados en un archivo.

## 📊 Ejemplo de Salida
El reportero visual organiza los hallazgos por severidad:
- 🔴 **CRITICAL**: Riesgo inmediato (SQLi, Cmd Injection).
- 🟠 **HIGH**: Riesgo alto (LFI, Stored XSS).
- 🟡 **MEDIUM**: Riesgo moderado (Reflected XSS).
- 🟢 **LOW**: Riesgo bajo.

## ⚠️ Aviso Legal
Esta herramienta ha sido creada con fines educativos y para su uso en entornos controlados (CTF, laboratorios). El uso de esta herramienta contra objetivos sin autorización es ilegal.
