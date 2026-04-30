# Laboratorio SIEM con Wazuh, WannaCry y Snort

Este repositorio contiene un laboratorio SIEM basado en Wazuh Docker single-node.
El objetivo es demostrar dos flujos de deteccion complementarios:

1. **WannaCry desde PCAP**: conversion de trafico historico a syslog enriquecido,
   ingesta por el manager y reglas de comportamiento SMB/NetBIOS.
2. **Snort en tiempo real**: sensor Snort dentro de un contenedor `victim`,
   envio de alertas mediante Wazuh agent y correlacion de una kill-chain de red.

El stack activo esta en:

```text
single-node/
```

## Arquitectura General

```text
                         +----------------+
                         | Wazuh Dashboard|
                         +--------+-------+
                                  |
                                  v
+----------------+        +-------+-------+        +---------------+
| Replay PCAP    | -----> | Wazuh Manager | -----> | Wazuh Indexer |
| WannaCry syslog|        | rules/decoders|        | wazuh-alerts-*|
+----------------+        +-------+-------+        +---------------+
                                  ^
                                  |
                       +----------+----------+
                       | Wazuh Agent         |
                       | victim + Snort      |
                       +----------+----------+
                                  ^
                                  |
                              attacker
```

Hay dos tipos de ingesta:

- **WannaCry**: el manager lee `/var/log/wannacry-syslog.log` como `localfile`.
- **Snort**: el contenedor `victim` ejecuta Snort y un Wazuh agent; el agent lee
  `/var/log/snort/alert` con `log_format=snort-full` y envia eventos al manager.

## Ficheros Relevantes

### Wazuh Docker

```text
single-node/docker-compose.yml
single-node/config/wazuh_cluster/wazuh_manager.conf
single-node/config/wazuh_cluster/local_decoder.xml
single-node/config/wazuh_cluster/local_rules.xml
single-node/config/wazuh_cluster/snort_correlation_rules.xml
```

### WannaCry

```text
pcap_to_syslog.py
replay_wannacry_syslog.py
single-node/config/wannacry_malicious_logs/wannacry_malicious_logs.pcap
single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog_full.log
single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog.log
```

### Snort

```text
single-node/docker/victim/Dockerfile
single-node/docker/victim/victim-entrypoint.sh
single-node/docker/victim/snort-lab-chain.rules
single-node/docker/attacker/Dockerfile
single-node/docker/attacker/attack-simulate.sh
single-node/scripts/run-snort-chain-scenario.ps1
single-node/scripts/run-snort-chain-scenario.sh
```

## Cambios Realizados

## 1. Ingesta WannaCry desde PCAP

### Problema inicial

El PCAP de WannaCry se convertia a un fichero syslog completo y se montaba en el
manager. Esto no siempre generaba alertas porque Wazuh procesa de forma fiable
las **lineas nuevas por append**, no necesariamente un fichero historico ya
existente antes de arrancar el collector.

Ademas, las reglas originales alertaban con severidad alta por cada evento hacia
`dport=445`, generando demasiado ruido: en la muestra hay mas de 25.000 eventos
SMB.

### Cambios en `pcap_to_syslog.py`

Antes:

- Se generaba directamente `wannacry_malicious_syslog.log`.
- Se usaba `datetime.now()` para casi todos los eventos.
- El campo principal era `info`, con texto como `TCP SMB flags=SYN`.

Ahora:

- Se genera un fichero fuente completo:

  ```text
  single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog_full.log
  ```

- Se usan los timestamps reales del PCAP.
- Se enriquecen los eventos con campos estructurados:

  ```text
  src
  dst
  sport
  dport
  proto
  service
  flags
  len
  direction
  broadcast
  flow_id
  info
  ```

Ejemplo:

```text
May 18 10:12:07 wannacry-pcap tshark: src=192.168.116.149 dst=192.168.116.138 sport=49367 dport=445 proto=tcp service=SMB flags="SYN" len=52 direction=internal_to_internal broadcast=false flow_id="tcp:192.168.116.149:49367-192.168.116.138:445" info="TCP SMB flags=SYN"
```

### Por que se hizo asi

Los campos estructurados permiten crear reglas sobre atributos concretos
(`dstport`, `network.service`, `tcp.flags`, etc.) en vez de buscar texto dentro
de `info`. Esto reduce falsos positivos y facilita explicar la deteccion.

Usar timestamps reales del PCAP permite que las reglas con `frequency` y
`timeframe` representen mejor la secuencia original del ataque.

## 2. Decoder WannaCry

Fichero:

```text
single-node/config/wazuh_cluster/local_decoder.xml
```

Se anadio el decoder `tshark-wannacry`, asociado al programa `tshark`.

Extrae:

```text
srcip
dstip
srcport
dstport
protocol
network.service
tcp.flags
packet.len
network.direction
network.broadcast
flow.id
packet.info
```

### Por que es importante

Sin decoder, Wazuh solo ve texto plano. Con decoder, las reglas pueden usar
campos normalizados. Por ejemplo, una regla puede decir:

```xml
<dstport>445</dstport>
<field name="network.service">^SMB$</field>
<field name="tcp.flags">^SYN$</field>
```

Esto hace que la deteccion sea mas robusta y explicable.

## 3. Reglas WannaCry

Fichero:

```text
single-node/config/wazuh_cluster/local_rules.xml
```

Las reglas se reorganizaron para separar observacion, intento de conexion,
fallo y comportamiento anomalo.

| Regla | Nivel | Descripcion |
| --- | ---: | --- |
| `100200` | 3 | Evento PCAP decodificado |
| `100201` | 5 | Trafico SMB observado en TCP/445 |
| `100202` | 4 | Trafico NetBIOS |
| `100203` | 7 | Intento de conexion SMB con `SYN` |
| `100204` | 8 | Reset SMB despues de actividad en 445 |
| `100205` | 10 | Posible escaneo SMB: muchos `SYN` desde la misma IP |
| `100206` | 12 | Posible movimiento lateral WannaCry: alto volumen SMB desde la misma IP |
| `100207` | 6 | Descubrimiento NetBIOS broadcast |
| `100208` | 10 | Reconocimiento de cuentas si aparece `SAM LOGON` |
| `100209` | 8 | Enumeracion fallida si aparece `user unknown` |

### Por que se hizo asi

TCP/445 por si solo no significa explotacion: tambien puede ser trafico SMB
normal. La alerta critica debe depender de comportamiento:

- muchos intentos;
- mismo origen;
- ventana temporal corta;
- volumen alto;
- relacion con NetBIOS/SMB.

Por eso las reglas criticas usan `frequency`, `timeframe` y `same_source_ip`.

## 4. Replay Secuencial de WannaCry

Fichero:

```text
replay_wannacry_syslog.py
```

Este script toma el fichero completo `wannacry_malicious_syslog_full.log` y va
escribiendo eventos de forma secuencial en:

```text
single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog.log
```

Ese fichero esta montado en el manager como:

```text
/var/log/wannacry-syslog.log
```

### Por que se hizo asi

Wazuh genera alertas de forma fiable cuando llegan lineas nuevas. El replay
simula una fuente viva de logs: el manager ve eventos nuevos y las reglas se
pueden disparar en tiempo real.

## 5. Integracion de Snort

La integracion Snort se porto desde el laboratorio `../SIEM`.

Se copiaron y adaptaron:

```text
single-node/docker/victim/
single-node/docker/attacker/
single-node/scripts/run-snort-chain-scenario.sh
single-node/scripts/run-snort-chain-scenario.ps1
single-node/config/wazuh_cluster/snort_correlation_rules.xml
```

Tambien se modifico:

```text
single-node/docker-compose.yml
```

para anadir:

- servicio `victim`;
- servicio `attacker`;
- volumen persistente del agente Wazuh del victim;
- volumen de logs Snort;
- montaje de reglas Snort en el manager.

### Como funciona

El contenedor `victim` contiene:

- Snort;
- Wazuh agent;
- servidor HTTP simple en puerto `8080`;
- reglas Snort de laboratorio.

El contenedor `attacker` genera trafico contra `victim`.

Snort escribe alertas en:

```text
/var/log/snort/alert
```

El Wazuh agent del mismo contenedor lee ese fichero con:

```xml
<log_format>snort-full</log_format>
```

y envia los eventos al manager.

### Por que no se monta el log Snort directamente en el manager

Snort es un sensor de red. Lo mas realista es colocarlo junto al host o red que
se quiere monitorizar y enviar sus alertas mediante un agente. Por eso:

```text
Snort -> Wazuh agent -> Wazuh manager
```

es mejor que:

```text
Snort log montado directamente en manager
```

Ademas, Wazuh ya incluye decoders/reglas para Snort. Las reglas de correlacion
se apoyan en el SID base `20101`, por lo que no se necesita un decoder Snort
personalizado.

## 6. Reglas Snort

Fichero:

```text
single-node/docker/victim/snort-lab-chain.rules
```

Reglas creadas:

| Etapa | SID Snort | Descripcion |
| --- | --- | --- |
| 1 | `1010101` | Reconocimiento ICMP |
| 2 | `1010102` | Escaneo SYN a puertos conocidos |
| 3 | `1010103` | Peticiones HTTP a rutas sensibles |
| 4 | `1010104` | Intento de SQLi o path traversal |
| 5 | `1010105` | POST con User-Agent automatizado |

Snort arranca con:

```text
-A fast -k none
```

`-A fast` genera alertas en formato compatible con `snort-full`.

`-k none` evita problemas de checksum en redes Docker, donde el checksum puede
delegarse al host y Snort podria ignorar trafico HTTP valido.

## 7. Reglas de Correlacion Snort en Wazuh

Fichero:

```text
single-node/config/wazuh_cluster/snort_correlation_rules.xml
```

Reglas:

| Regla Wazuh | Nivel | Descripcion |
| --- | ---: | --- |
| `100360` | 5 | Etapa 1 detectada |
| `100361` | 6 | Etapa 2 detectada |
| `100362` | 8 | Etapa 3 detectada |
| `100363` | 10 | Etapa 4 detectada |
| `100364` | 11 | Etapa 5 detectada |
| `100390` | 12 | Al menos 3 etapas desde el mismo origen en 600 s |
| `100391` | 15 | Kill-chain completa, 5 etapas desde el mismo origen |

Las reglas `100360..100364` etiquetan cada etapa. Las reglas `100390` y
`100391` correlan por mismo origen usando:

```xml
<if_matched_group>snort_lab_chain</if_matched_group>
<same_source_ip />
```

### Por que se hizo asi

Una alerta aislada puede ser poco concluyente. Varias etapas encadenadas desde
el mismo origen tienen mucho mas valor analitico. La correlacion convierte
eventos tecnicos de Snort en una narrativa de ataque.

## Arranque del Laboratorio

Desde PowerShell, partiendo de la raiz del proyecto (`wazuh-docker`):

```powershell
cd single-node
docker compose up -d --build
docker compose ps
```

Tras cambios en reglas o decoders:

```powershell
docker compose restart wazuh.manager
```

Comprobar agente Snort:

```powershell
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
```

Debe aparecer `victim-agent` como `Active`.

## Test 1: Escenario WannaCry

### 1. Generar fichero completo desde PCAP

Desde la raiz del proyecto (`wazuh-docker`):

```powershell
python pcap_to_syslog.py
```

Salida esperada:

```text
wannacry_malicious_syslog_full.log
```

### 2. Preparar fichero vivo vacio

```powershell
python replay_wannacry_syslog.py --reset-only
```

Esto vacia:

```text
single-node/config/wannacry_malicious_logs/wannacry_malicious_syslog.log
```

### 3. Arrancar Wazuh

```powershell
cd single-node
docker compose up -d --build
docker compose restart wazuh.manager
```

### 4. Lanzar replay

Vuelve a la raiz del proyecto (`wazuh-docker`) desde `single-node`:

```powershell
cd ..
python replay_wannacry_syslog.py --delay 0.02
```

Para demo rapida:

```powershell
python replay_wannacry_syslog.py --delay 0 --limit 2000
```

### 5. Ver alertas en el manager

```powershell
cd single-node
docker compose exec wazuh.manager bash -lc "tail -n 300 /var/ossec/logs/alerts/alerts.log | grep -E '10020[0-9]'"
```

### 6. Consultas en Dashboard

Eventos WannaCry:

```text
rule.groups:wannacry
```

SMB:

```text
rule.id:(100201 OR 100203 OR 100205 OR 100206)
```

Movimiento lateral probable:

```text
rule.id:100206
```

## Test 2: Escenario Snort

### 1. Arrancar stack

Desde la raiz del proyecto (`wazuh-docker`):

```powershell
cd single-node
docker compose up -d --build
docker compose restart wazuh.manager
```

### 2. Verificar agente

```powershell
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
```

Debe aparecer:

```text
victim-agent ... Active
```

### 3. Ejecutar escenario PowerShell

```powershell
.\scripts\run-snort-chain-scenario.ps1
```

Si PowerShell bloquea el script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\run-snort-chain-scenario.ps1
```

### 4. Comprobar alertas Snort en victim

```powershell
docker compose exec victim tail -n 80 /var/log/snort/alert
```

Debes ver mensajes como:

```text
LAB Stage1 Reconnaissance: ICMP echo probe
LAB Stage2 Service Discovery: SYN probe on well-known port
LAB Stage3 Initial Access: HTTP request to sensitive path
LAB Stage4 Exploit attempt: SQLi or path-traversal payload in HTTP URI
LAB Stage5 Exfiltration/C2: HTTP POST with automation User-Agent
```

### 5. Comprobar alertas en Wazuh

```powershell
docker compose exec wazuh.manager bash -lc "tail -n 500 /var/ossec/logs/alerts/alerts.log | grep -E 'Rule: 10036[0-4]|Rule: 10039[01]'"
```

### 6. Consultas en Dashboard

Eventos Snort crudos:

```text
agent.name:"victim-agent" AND location:"/var/log/snort/alert"
```

Etapas etiquetadas:

```text
agent.name:"victim-agent" AND rule.id:(100360 OR 100361 OR 100362 OR 100363 OR 100364)
```

Correlacion final:

```text
agent.name:"victim-agent" AND rule.id:(100390 OR 100391)
```

## Troubleshooting

### Docker no arranca o no hay API

Comprueba que Docker Desktop esta abierto. Si `docker compose ps` falla, Wazuh
no podra levantarse ni ejecutar escenarios.

### Cambios de reglas no aparecen

Reinicia el manager:

```powershell
docker compose restart wazuh.manager
docker compose logs wazuh.manager --tail=200
```

### `victim-agent` no aparece

Revisa logs del victim:

```powershell
docker compose logs victim --tail=160
```

Si hay estado antiguo del agente:

```powershell
docker compose stop victim
docker volume rm single-node_victim-wazuh-agent
docker compose up -d victim
```

### Snort no genera alertas HTTP

Revisar proceso y errores:

```powershell
docker compose exec victim ps aux
docker compose exec victim tail -n 120 /var/log/snort/snort.stderr.log
```

### El script Bash no funciona en Windows

Usa la version PowerShell:

```powershell
.\scripts\run-snort-chain-scenario.ps1
```

El error:

```text
execvpe(/bin/bash) failed: No such file or directory
```

significa que el `bash` invocado es WSL y no tiene `/bin/bash` disponible.

## Documentos Complementarios

```text
WANNACRY_DETECTION_CHANGES.md
SNORT_INTEGRATION.md
CODEX_CONTEXT.md
```

`WANNACRY_DETECTION_CHANGES.md` explica con mas detalle los cambios especificos
del replay y reglas WannaCry.

`SNORT_INTEGRATION.md` explica con mas detalle la integracion Snort.

`CODEX_CONTEXT.md` resume el estado del proyecto para futuros agentes de Codex.
