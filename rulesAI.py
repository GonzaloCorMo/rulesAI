#!/usr/bin/env python3

import argparse
import requests
import os
import re
import subprocess
import time
import sys
import shutil

# Configuración de rutas
INSTALL_DIR = "/usr/local/rulesAI"
RULES_DIR = os.path.join(INSTALL_DIR, "rules")
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"
BIN_PATH = "/usr/local/bin/rai"

# Asegurar que el directorio de reglas existe
os.makedirs(RULES_DIR, exist_ok=True)

# Expresión regular para validar reglas de Suricata
SURICATA_RULE_REGEX = r'^(alert|drop|reject|pass)\s+\w+\s+[!?\d.]+/\d+\s+[<>]?\s+\d+\s+\(\s*msg\s*:\s*".+?";\s*sid\s*:\s*\d+;\s*rev\s*:\s*\d+;\s*\)$'

def mostrar_cargando():
    print("🕓 Generando regla, por favor espere", end="", flush=True)
    for _ in range(5):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print()

def modelo_existe(modelo):
    """Verifica si el modelo está instalado en Ollama."""
    try:
        resultado = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        modelos_instalados = [line.split(" ")[0] for line in resultado.stdout.splitlines() if line]
        return modelo in modelos_instalados
    except Exception as e:
        print(f"❌ Error al verificar los modelos de Ollama: {e}")
        return False

def generar_regla(consulta, modelo):
    """Genera una regla de Suricata usando Ollama con formato adecuado para archivos .rules."""
    if not modelo:
        modelo = "mistral:latest"  # Asignar modelo por defecto si no se especifica

    if not modelo_existe(modelo):
        print(f"❌ Error: El modelo '{modelo}' no está instalado en Ollama.")
        print("🔎 Usa 'ollama list' para ver los modelos disponibles.")
        return None

    # Instrucciones específicas para el formato correcto
    prompt = f"""
    Genera una regla de Suricata para detectar: {consulta}.
    Devuelve la salida en el siguiente formato:

    - La primera línea debe ser un comentario con el título de la detección.  
    - Luego, incluye comentarios explicando la lógica de la regla.  
    - Finalmente, proporciona la regla en sintaxis válida de Suricata sin comillas ni bloques de código.  

    Ejemplo de formato esperado:

    # {consulta}
    # Descripción: Explicación breve de lo que detecta la regla.
    # Detalles técnicos: Explicación de cada campo.

    alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Brute Force Detected"; flow:established,to_server; content:"SSH-2.0"; nocase; sid:100002; rev:1;)
    """

    # Mostrar animación mientras se espera la respuesta
    mostrar_cargando()

    response = requests.post("http://localhost:11434/api/generate", json={
        "model": modelo,
        "prompt": prompt,
        "stream": False
    })

    if response.status_code == 200:
        data = response.json()
        regla = data.get("response", "").strip()

        # Asegurar que la salida tiene el formato correcto
        if not regla.startswith("#"):
            regla = f"# {consulta}\n" + regla  # Agregar título como comentario si no está presente
        
        return regla
    else:
        print("❌ Error en la API de Ollama:", response.text)
        return None


def validar_sintaxis(regla):
    return bool(re.match(SURICATA_RULE_REGEX, regla))

def validar_con_suricata(archivo):
    print("🔍 Validando reglas en Suricata...")
    try:
        resultado = subprocess.run(
            ["suricata", "-T", "-c", SURICATA_CONFIG, "-S", archivo],
            capture_output=True,
            text=True,
            check=False
        )
        if resultado.returncode == 0:
            print("✅ Las reglas son válidas para Suricata.")
            return True
        else:
            print("❌ Error en la validación de Suricata:\n", resultado.stderr)
            return False
    except FileNotFoundError:
        print("❌ Suricata no está instalado o no se encuentra en la ruta del sistema.")
        return False

def guardar_regla(regla, archivo):
    with open(archivo, "a") as f:
        f.write(regla + "\n")
    print(f"[+] Regla guardada en {archivo}")

def aplicar_reglas():
    print("🔄 Aplicando reglas en Suricata...")
    subprocess.run(["suricata-update"], check=True)
    subprocess.run(["systemctl", "restart", "suricata"], check=True)
    print("✅ Suricata actualizado con nuevas reglas.")

def desinstalar():
    """Elimina rulesAI del sistema completamente."""
    print("⚠️ Esto eliminará rulesAI y todas sus reglas.")
    confirmar = input("¿Seguro que quieres continuar? (y/N): ").strip().lower()
    
    if confirmar != "y":
        print("❌ Desinstalación cancelada.")
        return
    
    try:
        if os.path.exists(INSTALL_DIR):
            shutil.rmtree(INSTALL_DIR)
            print(f"🗑️ Eliminado: {INSTALL_DIR}")
        
        if os.path.exists(BIN_PATH):
            os.remove(BIN_PATH)
            print(f"🗑️ Eliminado: {BIN_PATH}")

        print("✅ rulesAI ha sido completamente desinstalado.")
    except Exception as e:
        print(f"❌ Error al desinstalar rulesAI: {e}")

def main():
    parser = argparse.ArgumentParser(description="Genera reglas de Suricata usando IA local con Ollama.")
    parser.add_argument("-c", "--consulta", type=str, help="Descripción de la amenaza para generar la regla.")
    parser.add_argument("-o", "--output", type=str, help="Archivo donde guardar la regla (por defecto en 'rules/').")
    parser.add_argument("-i", "--input", type=str, help="Archivo existente al que se añadirán las reglas sin eliminar las anteriores.")
    parser.add_argument("--apply", action="store_true", help="Aplicar las reglas en Suricata después de generarlas.")
    parser.add_argument("--validate", action="store_true", help="Validar la regla antes de guardarla.")
    parser.add_argument("--validate-suricata", action="store_true", help="Validar las reglas con Suricata.")
    parser.add_argument("--model", type=str, default="mistral:latest", help="Modelo de Ollama a utilizar (por defecto: mistral:latest)")
    parser.add_argument("--uninstall", action="store_true", help="Desinstalar rulesAI completamente.")

    args = parser.parse_args()

    if args.uninstall:
        desinstalar()
        return

    if not args.consulta:
        print("❌ Debes proporcionar una consulta con '-c'. Usa '-h' para ver las opciones.")
        return

    regla = generar_regla(args.consulta, args.model)

    if regla:
        print("\n🔹 Regla Generada:\n", regla)

        if args.validate:
            if not validar_sintaxis(regla):
                print("❌ La regla generada no tiene una sintaxis válida. No se guardará.")
                return
            print("✅ La regla tiene una sintaxis válida.")

        archivo_salida = args.input if args.input else (args.output if args.output else os.path.join(RULES_DIR, "default.rules"))
        guardar_regla(regla, archivo_salida)

        if args.validate_suricata:
            if not validar_con_suricata(archivo_salida):
                print("⚠️ La validación con Suricata falló. Revisa el archivo de reglas.")
                return

        if args.apply:
            aplicar_reglas()

if __name__ == "__main__":
    main()
