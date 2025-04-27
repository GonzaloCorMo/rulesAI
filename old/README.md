# rulesAI

rulesAI es una herramienta que genera reglas para Suricata utilizando inteligencia artificial local con Ollama. Permite generar, validar y aplicar reglas de detección de amenazas de forma automática.

## Instalación

Se recomienda ejecutar la instalación con permisos de superusuario (`sudo`). Para instalar rulesAI, usa:

```bash
sudo bash install.sh
```

El script de instalación:
1. Pregunta si deseas instalar Ollama (necesario para rulesAI).
2. Pregunta si deseas descargar el modelo `mistral:latest`.
3. Crea la estructura de archivos en `/usr/local/rulesAI`.
4. Copia el script `rulesAI.py` a la carpeta de instalación.
5. Crea un alias `rai` para ejecutar el comando desde cualquier lugar.

## Uso

Una vez instalado, puedes generar reglas de Suricata con el siguiente comando:

```bash
sudo -E rai -c "Detectar tráfico SSH sospechoso"
```

Esto generará una regla de detección basada en la descripción proporcionada y la guardará en el directorio de reglas.

### Opciones disponibles

- `-c, --consulta "texto"` → Especifica la amenaza a detectar (obligatorio).
- `-o, --output "archivo.rules"` → Define el archivo donde se guardará la regla (por defecto en `rules/`).
- `-i, --input "archivo.rules"` → Agrega la regla a un archivo existente.
- `--apply` → Aplica las reglas generadas en Suricata.
- `--validate` → Valida la sintaxis de la regla antes de guardarla.
- `--validate-suricata` → Valida las reglas con Suricata antes de aplicarlas.
- `--model "modelo"` → Especifica el modelo de IA a usar (por defecto `mistral:latest`).
- `--uninstall` → Desinstala rulesAI completamente.

### Ejemplos de uso

Generar una regla y guardarla en un archivo específico:
```bash
sudo -E rai -c "Detectar tráfico malicioso en el puerto 443" -o custom.rules
```

Generar una regla y validarla antes de guardarla:
```bash
sudo -E rai -c "Detectar tráfico de malware en HTTP" --validate
```

Generar y aplicar reglas directamente en Suricata:
```bash
sudo -E rai -c "Detectar intentos de explotación de RCE" --apply
```

Validar un archivo de reglas con Suricata:
```bash
sudo -E rai --validate-suricata -i custom.rules
```

## Desinstalación

Si deseas eliminar rulesAI del sistema, usa:
```bash
sudo -E rai --uninstall
```

Esto eliminará la carpeta de instalación y el alias `rai`.

## Requisitos
- Python 3
- Suricata instalado y configurado
- Ollama con un modelo de IA compatible (`mistral:latest` recomendado)

## Notas
Se recomienda ejecutar todos los comandos con `sudo -E` para evitar problemas de permisos al acceder a las configuraciones de Suricata y directorios protegidos.

---

© 2024 rulesAI - Proyecto de generación de reglas para Suricata con IA local.

