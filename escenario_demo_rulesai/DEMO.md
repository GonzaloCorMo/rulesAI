# Demo - RulesAI + Suricata limpio y funcional

## 🚀 Pasos para ejecutar:

1. Extrae este zip en `~/Escritorio/demo_rulesai_final/`
2. Entra a la carpeta:

```bash
cd ~/Escritorio/demo_rulesai_final
```

3. Levanta el entorno:

```bash
docker compose up -d
```

4. Usa RulesAI:

```bash
rulesai-gui
```
o

```bash
rulesai -c "Detectar tráfico" -o ./rules/custom.rules
```

5. Reinicia Suricata para cargar nuevas reglas:

```bash
docker restart suricata
```

6. Simula tráfico desde el attacker:

```bash
docker exec -it attacker bash
curl http://neverssl.com
```

7. Verifica alertas en vivo:

```bash
docker exec -it suricata tail -f /var/log/suricata/fast.log

```