
from setuptools import setup, find_packages

setup(
    name="rulesai",
    version="1.0",
    description="Generador de reglas de Suricata con IA local (Ollama), GUI y CLI",
    author="Gonzalo Cordeiro",
    packages=find_packages(),
    install_requires=["PyQt5", "requests"],
    entry_points={
        "console_scripts": [
            "rulesai-gui=rulesai.gui.app:main",
            "rulesai=rulesai.cli:main"
        ]
    },
    python_requires=">=3.7",
)
