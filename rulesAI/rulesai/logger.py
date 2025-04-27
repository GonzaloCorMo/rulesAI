import logging
import os
from datetime import datetime

LOG_DIR = os.path.expanduser("~/.rulesai")
os.makedirs(LOG_DIR, exist_ok=True)

log_file = os.path.join(LOG_DIR, "rulesai.log")

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def get_logger(name="rulesai"):
    return logging.getLogger(name)
