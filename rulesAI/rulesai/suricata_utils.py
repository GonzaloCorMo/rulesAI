import subprocess
from rulesai.logger import get_logger

logger = get_logger()
SURICATA_CONFIG = "/etc/suricata/suricata.yaml"

def validar_con_suricata(archivo):
    logger.info(f"Validando reglas en Suricata: {archivo}")
    try:
        resultado = subprocess.run(
            ["suricata", "-T", "-c", SURICATA_CONFIG, "-S", archivo],
            capture_output=True,
            text=True
        )
        if resultado.returncode == 0:
            logger.info("Las reglas son válidas para Suricata.")
            return True
        else:
            logger.error(f"Error en validación Suricata: {resultado.stderr}")
            return False
    except FileNotFoundError:
        logger.error("Suricata no está instalado.")
        return False

def aplicar_reglas():
    logger.info("Aplicando reglas en Suricata...")
    subprocess.run(["suricata-update"], check=True)
    subprocess.run(["systemctl", "restart", "suricata"], check=True)
    logger.info("Suricata reiniciado con nuevas reglas.")
