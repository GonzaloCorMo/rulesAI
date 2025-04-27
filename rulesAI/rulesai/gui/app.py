
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QTextEdit,
                             QFileDialog, QMessageBox, QComboBox, QDialog, QProgressBar)
from PyQt5.QtCore import Qt, QTimer
import sys
import requests


def guardar_regla(regla, archivo):
    with open(archivo, "a") as f:
        f.write(regla + "\n")


class LoadingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generando regla...")
        self.setModal(True)
        self.setFixedSize(300, 100)
        layout = QVBoxLayout()
        label = QLabel("Por favor espera... Se está generando la regla.")
        label.setAlignment(Qt.AlignCenter)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # Indeterminate mode
        layout.addWidget(label)
        layout.addWidget(self.progress)
        self.setLayout(layout)


class RulesAIGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RulesAI - Generador de Reglas Suricata")
        self.setGeometry(300, 300, 600, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.label_consulta = QLabel("Descripción de la amenaza:")
        self.input_consulta = QLineEdit()
        self.label_prompt = QLabel("Prompt personalizado (opcional):")
        self.input_prompt = QTextEdit()
        self.label_modelo = QLabel("Modelo Ollama:")
        self.model_select = QComboBox()
        self.cargar_modelos_disponibles()
        self.btn_generar = QPushButton("Generar Regla")
        self.btn_generar.clicked.connect(self.generar_regla)
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.btn_guardar = QPushButton("Guardar Regla")
        self.btn_guardar.clicked.connect(self.guardar_regla)
        self.btn_guardar.setEnabled(False)
        layout.addWidget(self.label_consulta)
        layout.addWidget(self.input_consulta)
        layout.addWidget(self.label_prompt)
        layout.addWidget(self.input_prompt)
        layout.addWidget(self.label_modelo)
        layout.addWidget(self.model_select)
        layout.addWidget(self.btn_generar)
        layout.addWidget(self.output_area)
        layout.addWidget(self.btn_guardar)
        self.setLayout(layout)

    def cargar_modelos_disponibles(self):
        try:
            response = requests.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                modelos = [m['name'] for m in response.json().get("models", [])]
                self.model_select.addItems(modelos)
                if "codellama:13b" in modelos:
                    self.model_select.setCurrentIndex(modelos.index("codellama:13b"))
                elif modelos:
                    self.model_select.setCurrentIndex(0)
        except Exception as e:
            QMessageBox.warning(self, "Modelos no disponibles", f"No se pudieron cargar los modelos de Ollama:\n{str(e)}")

    def generar_prompt(self, consulta, prompt_personalizado):
        if prompt_personalizado:
            return prompt_personalizado
        return (
            f"Genera solo una regla válida para Suricata, precedida por un comentario en una línea que resuma la descripción: '{consulta}'. "
            f"El resultado debe ser exactamente así:\n"
            f"# Descripción en forma de comentario\nalert ..."
        )

    def generar_regla(self):
        consulta = self.input_consulta.text().strip()
        prompt_personalizado = self.input_prompt.toPlainText().strip()
        modelo = self.model_select.currentText()
        if not consulta and not prompt_personalizado:
            QMessageBox.warning(self, "Error", "Debes ingresar una descripción o un prompt personalizado.")
            return
        dialogo = LoadingDialog(self)
        QTimer.singleShot(100, lambda: self._generar_regla(dialogo, consulta, modelo, prompt_personalizado))
        dialogo.exec_()

    def _generar_regla(self, dialogo, consulta, modelo, prompt_personalizado):
        regla = ""
        try:
            response = requests.post("http://localhost:11434/api/generate", json={
                "model": modelo,
                "prompt": self.generar_prompt(consulta, prompt_personalizado),
                "stream": False
            })
            if response.status_code == 200:
                regla = response.json().get("response", "").strip()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al contactar con Ollama:\n{str(e)}")
        finally:
            dialogo.close()
        self.output_area.setPlainText(regla)
        self.btn_guardar.setEnabled(bool(regla))

    def guardar_regla(self):
        regla = self.output_area.toPlainText().strip()
        if not regla:
            QMessageBox.warning(self, "Error", "No hay ninguna regla para guardar.")
            return
        archivo, _ = QFileDialog.getSaveFileName(self, "Guardar regla", "default.rules", "Reglas (*.rules)")
        if archivo:
            guardar_regla(regla, archivo)
            QMessageBox.information(self, "Guardado", f"Regla guardada en: {archivo}")

def main():
    app = QApplication(sys.argv)
    gui = RulesAIGUI()
    gui.show()
    sys.exit(app.exec_())
