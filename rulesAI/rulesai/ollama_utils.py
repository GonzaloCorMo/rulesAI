import subprocess
from rulesai.logger import get_logger

logger = get_logger()

def modelo_existe(modelo):
    try:
        resultado = subprocess.run(["ollama", "list"], capture_output=True, text=True, check=True)
        modelos = [line.split()[0] for line in resultado.stdout.splitlines() if line]
        return modelo in modelos
    except Exception as e:
        logger.error(f"Error verificando modelo Ollama: {e}")
        return False
