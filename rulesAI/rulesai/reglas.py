import os
import re
import requests
from rulesai.ollama_utils import modelo_existe
from rulesai.logger import get_logger

logger = get_logger()

RULES_DIR = os.path.expanduser("~/.rulesai/rules")
SURICATA_RULE_REGEX = r'^(alert|drop|reject|pass)\s+\w+\s+[!?\d.]+/\d+\s+[<>]?\s+\d+\s+\(\s*msg\s*:\s*".+?";\s*sid\s*:\s*\d+;\s*rev\s*:\s*\d+;\s*\)$'
os.makedirs(RULES_DIR, exist_ok=True)

def generar_regla(consulta, modelo):
    if not modelo:
        modelo = "mistral:latest"

    if not modelo_existe(modelo):
        logger.error(f"Modelo '{modelo}' no encontrado en Ollama.")
        return None

    prompt = f"""
    Genera una regla de Suricata para detectar: {consulta}.
    Devuelve solo la salida en formato:
    - Comentario con título
    - Comentarios con explicación
    - Regla válida sin código markdown
    """

    logger.info(f"Generando regla con modelo: {modelo}")
    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": modelo,
            "prompt": prompt,
            "stream": False
        })
        if response.status_code == 200:
            regla = response.json().get("response", "").strip()
            if not regla.startswith("#"):
                regla = f"# {consulta}\n" + regla
            return regla
        else:
            logger.error(f"Error desde API Ollama: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Excepción al generar regla: {e}")
        return None

def validar_sintaxis(regla):
    return bool(re.match(SURICATA_RULE_REGEX, regla))

def guardar_regla(regla, archivo):
    if not archivo:
        archivo = os.path.join(RULES_DIR, "default.rules")
    with open(archivo, "a") as f:
        f.write(regla + "\n")
    logger.info(f"Regla guardada en {archivo}")
    return archivo

def generar_y_guardar_regla(consulta, archivo, modelo):
    regla = generar_regla(consulta, modelo)
    if not regla:
        logger.error("No se generó ninguna regla.")
        return False, None

    if not validar_sintaxis(regla):
        logger.error("La sintaxis de la regla generada no es válida.")
        return False, None

    logger.info(f"Regla generada exitosamente para: {consulta}")
    path = guardar_regla(regla, archivo)
    return True, path
