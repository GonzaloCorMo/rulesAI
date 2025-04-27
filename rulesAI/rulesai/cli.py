
import argparse
import requests
import os
from rulesai.gui.app import guardar_regla

def generar_prompt(consulta, prompt_personalizado):
    if prompt_personalizado:
        return prompt_personalizado
    return (
        f"Genera solo una regla válida para Suricata, precedida por un comentario en una línea que resuma la descripción: '{consulta}'. "
        f"El resultado debe ser exactamente así:\n"
        f"# Descripción en forma de comentario\nalert ..."
    )

def main():
    parser = argparse.ArgumentParser(description="Generador de reglas para Suricata usando IA local")
    parser.add_argument('-c', '--consulta', type=str, help="Descripción de la amenaza")
    parser.add_argument('-p', '--prompt', type=str, help="Prompt personalizado completo (sin triples comillas)")
    parser.add_argument('-m', '--modelo', type=str, default='codellama:13b', help="Modelo Ollama a utilizar")
    parser.add_argument('-o', '--output', type=str, help="Archivo para guardar la regla generada")

    args = parser.parse_args()

    if not args.consulta and not args.prompt:
        print("❌ Debes proporcionar una descripción (-c) o un prompt personalizado (-p).")
        return

    print("⏳ Generando regla, por favor espera...")
    prompt = generar_prompt(args.consulta, args.prompt)

    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": args.modelo,
            "prompt": prompt,
            "stream": False
        })
        if response.status_code == 200:
            regla = response.json().get("response", "").strip()
            print("\n📜 Regla generada:\n")
            print(regla)
            if args.output:
                guardar_regla(regla, args.output)
                print(f"✅ Regla guardada en: {args.output}")
        else:
            print("❌ Error al generar la regla:", response.text)
    except Exception as e:
        print(f"❌ Error al contactar con Ollama: {e}")
