# RulesAI – Generador de Reglas Suricata con IA Local

**RulesAI** es una herramienta avanzada para generar reglas de detección de amenazas en Suricata utilizando inteligencia artificial local vía [Ollama](https://ollama.com/). Permite describir una amenaza y recibir una regla válida lista para usar, tanto desde la línea de comandos como desde una interfaz gráfica intuitiva.

## 🚀 Características

- ✅ Soporte para IA local con Ollama
- 🧠 Compatible con modelos como `codellama:13b`
- 🖥️ Interfaz gráfica con PyQt5
- 💻 Consola con opciones de prompt personalizado y guardado
- 📦 Fácil instalación con `pipx`
- 🔐 Uso local, sin necesidad de conexión a la nube

## 📋 Requisitos

- Python 3.7+
- [Ollama](https://ollama.com) instalado y corriendo localmente
- Modelo Ollama instalado (ej: `codellama:13b`)
- pipx (opcional, recomendado)

## ⚙️ Instalación

1. Clonar o descargar el proyecto:

```bash
unzip rulesai_gui_and_cli_final.zip
cd rulesai_full_project_ready
```

2. Instalar usando `pipx`:

```bash
pipx install .
```

> Esto instalará los comandos `rulesai` (modo consola) y `rulesai-gui` (modo gráfico)

## 🧪 Uso

### 🖥️ Interfaz gráfica

```bash
rulesai-gui
```

1. Introduce una descripción de la amenaza.
2. (Opcional) Escribe un prompt personalizado.
3. Selecciona el modelo Ollama.
4. Haz clic en “Generar Regla”.
5. Guarda la regla en un archivo `.rules`.

### 💻 Consola

```bash
rulesai -c "tráfico sospechoso por SSH" -m codellama:13b -o ssh.rules
```

Parámetros disponibles:
- `-c` o `--consulta`: Descripción de la amenaza
- `-p` o `--prompt`: Prompt personalizado
- `-m` o `--modelo`: Modelo Ollama a usar
- `-o` o `--output`: Archivo donde guardar la regla

## 📜 Ejemplo de salida

```
# Suspicious SSH scanning detected
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Possible SSH Scan"; flags:S; sid:100001;)
```

## 📄 Licencia

Consulta el archivo [LICENSE.md](LICENSE.md).

Este software es de uso personal y no comercial. Su modificación o redistribución no está permitida.

---

Desarrollado por **Gonzalo Cordeiro Mourelle**.