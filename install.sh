#!/bin/bash

INSTALL_DIR="/usr/local/rulesAI"
RULES_DIR="$INSTALL_DIR/rules"
BIN_PATH="/usr/local/bin/rai"
OLLAMA_MODEL="mistral:latest"  # Se usa la versión específica

# Función para preguntar sí/no
confirm() {
    while true; do
        read -rp "$1 (y/n): " respuesta
        case "$respuesta" in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Por favor, responde 'y' o 'n'." ;;
        esac
    done
}

# 1️⃣ Preguntar si desea instalar Ollama
echo "⚠️ Ollama es necesario para ruelesAI, si ya está instalado puedes saltar este paso."
if confirm "¿Deseas instalar Ollama ahora?"; then
    echo "📥 Instalando Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    # Verificamos si la instalación fue exitosa
    if ! which ollama &> /dev/null; then
        echo "❌ No se pudo instalar Ollama. Continuando con la instalación de rulesAI sin Ollama."
    else
        echo "✅ Ollama instalado correctamente."
    fi
else
    echo "❌ Instalación de Ollama cancelada. Continuando con la instalación de rulesAI sin Ollama."
fi

# 2️⃣ Preguntar si desea descargar el modelo 'mistral:latest'
echo "⚠️ Mistral:Latest es el modelo recomendado para ruelesAI, si ya está instalado puedes saltar este paso."
if confirm "¿Deseas instalar Mistral:Latest ahora?"; then
    if confirm "¿Deseas descargar '$OLLAMA_MODEL' ahora?"; then
        echo "📥 Descargando el modelo '$OLLAMA_MODEL'..."
        ollama pull "$OLLAMA_MODEL"
    else
        echo "❌ Instalación cancelada del modelo '$OLLAMA_MODEL'. Continuando sin el modelo."
    fi
else
    echo "❌ Instalación cancelada del modelo '$OLLAMA_MODEL'. Continuando sin el modelo."
fi

# 3️⃣ Crear directorio de instalación
echo "📂 Creando estructura de archivos en $INSTALL_DIR..."
mkdir -p "$RULES_DIR"

# 4️⃣ Copiar el script principal
echo "📜 Copiando el script principal..."
cp rulesAI.py "$INSTALL_DIR/rulesAI.py"
chmod +x "$INSTALL_DIR/rulesAI.py"

# 5️⃣ Crear enlace simbólico para el comando 'rai'
echo "🔗 Creando el comando 'rai' en /usr/local/bin..."
echo "#!/bin/bash" > "$BIN_PATH"
echo "python3 $INSTALL_DIR/rulesAI.py \"\$@\"" >> "$BIN_PATH"
chmod +x "$BIN_PATH"

# 6️⃣ Finalización
echo "✅ Instalación completada. Ahora puedes usar el comando 'rai'."
echo "Ejemplo de uso:  rai -c 'Detectar tráfico SSH sospechoso'"

