TRAVERSO FORENSICS - ANDROID DATA EXTRACTION TOOL

================================================================================

DESCRIPCIÓN:
------------
Herramienta forense para extracción de datos de aplicaciones Android
usando CVE-2024-0044 (Android 12/13)

REQUISITOS PREVIOS:
-------------------
- Python 3.8 o superior
- Android Debug Bridge (ADB) instalado y en el PATH
- Dispositivo Android conectado con USB Debugging habilitado
- APK de F-Droid (o similar) para el exploit

INSTALACIÓN:
------------

1. Instalar Python:
   - Python 3.8+
   - tkinter (incluido en la mayoría de instalaciones de Python)

2. Instalar dependencias Python:
   pip install -r requirements.txt

3. Instalar ADB (Android Debug Bridge):

   Windows:
   - Descargar Android Platform Tools de:
     https://developer.android.com/studio/releases/platform-tools
   - Extraer y agregar al PATH del sistema
   - Verificar: adb version

   Linux (Ubuntu/Debian):
   - sudo apt update
   - sudo apt install adb
   - Verificar: adb version

   macOS:
   - brew install android-platform-tools
   - Verificar: adb version

4. Descargar APK de F-Droid:
   - Visitar: https://f-droid.org/
   - Descargar F-Droid.apk
   - Colocar en la misma carpeta que el script

CONFIGURACIÓN DEL DISPOSITIVO:
-------------------------------
1. Habilitar Opciones de Desarrollador en Android:
   - Ir a Configuración > Acerca del teléfono
   - Tocar 7 veces en "Número de compilación"

2. Habilitar USB Debugging:
   - Ir a Configuración > Opciones de Desarrollador
   - Activar "Depuración USB"

3. Conectar dispositivo por USB:
   - Conectar cable USB
   - Aceptar autorización de depuración en el dispositivo
   - Verificar: adb devices

VERIFICAR INSTALACIÓN:
----------------------
python -c "import tkinter; import reportlab; print('OK')"
adb version
adb devices

EJECUTAR PROGRAMA:
------------------
python extractor_app.py

FUNCIONALIDADES:
----------------
✓ Detección automática de dispositivos Android
✓ Listado de aplicaciones instaladas
✓ Extracción de datos usando CVE-2024-0044
✓ Generación de hash SHA256 del archivo extraído
✓ Generación de reporte PDF con información del dispositivo
✓ Registro detallado (log) de todas las operaciones
✓ Interfaz gráfica moderna y fácil de usar

ESTRUCTURA DE SALIDA:
----------------------
extraction_[package]_[timestamp]/
├── wa.tar                          # Datos extraídos
├── [package]_[timestamp]_wa_tar_SHA256.txt  # Hash del tar
├── extraction_report_[timestamp].pdf        # Reporte en PDF
├── extraction_report_[timestamp]_SHA256.txt # Hash del PDF
└── extraction_log_[timestamp].txt           # Log de operaciones

DISPOSITIVOS COMPATIBLES:
--------------------------
- Android 12
- Android 13
- Dispositivos con CVE-2024-0044 sin parchear

REQUISITOS DE SEGURIDAD:
-------------------------
⚠️ Esta herramienta debe ser utilizada solo por:
- Personal autorizado de investigación forense
- Con orden judicial o autorización legal
- En dispositivos propios o con consentimiento

❌ NO usar para:
- Acceso no autorizado a dispositivos
- Violación de privacidad
- Actividades ilegales

SOLUCIÓN DE PROBLEMAS:
----------------------

Error: "adb: command not found"
   → ADB no está instalado o no está en el PATH
   → Instalar ADB según las instrucciones arriba

Error: "no devices/emulators found"
   → Dispositivo no conectado o USB debugging deshabilitado
   → Verificar conexión USB y autorizar en el dispositivo
   → Ejecutar: adb devices

Error: "APK not found"
   → F-Droid.apk no está en la carpeta del script
   → Descargar desde https://f-droid.org/

Error: "ImportError: No module named 'reportlab'"
   → pip install reportlab

Error: "Failed to create backup"
   → El exploit puede no funcionar en este dispositivo
   → Verificar versión de Android (12 o 13)
   → Verificar que el dispositivo no tenga parches de seguridad recientes

ARCHIVOS NECESARIOS:
--------------------
✓ extractor_app.py         # Script principal
✓ F-Droid.apk               # APK para el exploit
✓ requirements.txt           # Dependencias Python


NOTAS LEGALES:
--------------
- Uso exclusivo para análisis forense legal
- Requiere autorización legal para su uso
- El usuario es responsable del cumplimiento de leyes aplicables
- CVE-2024-0044 es una vulnerabilidad conocida y documentada

CHANGELOG:
----------
v1.0 - Versión actual
- Generación de reportes PDF
- Cálculo de hash SHA256
- Interfaz mejorada
- Logging detallado
- Extracción simplificada (sin descomprimir tar)

================================================================================
Copyright © 2026 Traverso Forensics. Todos los derechos reservados.
================================================================================
