# Schnittstellen.md — iobroker.fritzwireguard

> Letzte Aktualisierung: 2026-03-15 | Version: 0.2.7

---

## Übersicht

```
ioBroker-Host
  │
  ├─ [SCHNITTSTELLE 1] wg-quick (child_process)
  │         └─► Kernel WireGuard Interface wg-fritzwireguard
  │                     └─► VPN-Tunnel ─► entferntes Netz (192.168.178.0/24)
  │
  ├─ [SCHNITTSTELLE 2] TR-064 SOAP (HTTP über VPN-Tunnel)
  │         └─► FritzBox 192.168.178.1:49000
  │
  ├─ [SCHNITTSTELLE 3] TCP Tunnel Manager (net.createServer)
  │         ├─► 127.0.0.1:8085 ─► 192.168.178.55:80   (Kostal Piko)
  │         ├─► 127.0.0.1:8086 ─► 192.168.178.60:502  (Modbus-Gerät)
  │         └─► ... beliebig viele weitere Tunnel
  │
  ├─ [SCHNITTSTELLE 4] REST-API + Web-UI (http.createServer :8094)
  │         └─► Browser / andere Systeme
  │
  └─ [SCHNITTSTELLE 5] ioBroker Object Store (adapter-core)
            └─► fritzwireguard.0.*
```

---

## 1. WireGuard-Schnittstelle (System)

### 1.1 Befehle

| Befehl                             | Wann                             |
|------------------------------------|----------------------------------|
| `wg-quick up <tmpCfgPath>`         | onReady() / POST /api/connect    |
| `wg-quick down <tmpCfgPath>`       | onUnload() / POST /api/disconnect|
| `wg show wg-fritzwireguard`        | Jeder Poll-Zyklus                |

### 1.2 Temp-Config

```
Pfad:       /tmp/fritzwireguard/wg-fritzwireguard.conf
Rechte:     chmod 600
Inhalt:     Sanitized (kein DNS, kein 0.0.0.0/0)
Lebenszyklus: Erstellt _writeTempConfig(), gelöscht onUnload()
```

### 1.3 Config-Sanitizer

Aufruf: `sanitizeWgConfig(rawConfig)` → `{ cfg, warnings[] }`

| Regel                | Entfernt                    | Grund                              |
|----------------------|-----------------------------|------------------------------------|
| `DNS = ...`          | Alle DNS-Zeilen             | Kein systemweiter DNS-Overwrite    |
| `0.0.0.0/0`          | Aus AllowedIPs              | Kein Full-Tunnel                   |
| `::/0`               | Aus AllowedIPs              | Kein IPv6 Full-Tunnel              |

**Empfohlene AllowedIPs nach Sanitizing:**
```
AllowedIPs = 192.168.178.0/24
```
Nur Pakete an das entfernte Subnetz gehen durch den Tunnel.

### 1.4 Sudo-Konfiguration

```
# /etc/sudoers.d/iobroker-wireguard
iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg-quick
iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg
```

---

## 2. TR-064 SOAP-Schnittstelle

### 2.1 Verbindungsparameter

| Parameter | Wert                          |
|-----------|-------------------------------|
| Host      | config.fritzHost              |
| Port      | config.fritzPort (Std: 49000) |
| Protokoll | HTTP (über WireGuard-Tunnel)  |
| Auth      | HTTP Basic Auth               |
| Timeout   | 8000 ms                       |

### 2.2 Implementierte Endpunkte

#### WAN IP
```
Service: /igdupnp/control/WANIPConn1
Action:  urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress
→ State: fritzbox.externalIP
```

#### WAN Status / Uptime
```
Service: /igdupnp/control/WANIPConn1
Action:  urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo
→ States: fritzbox.uptime, fritzbox.connectionType
```

#### Geräte-Info
```
Service: /tr064/upnp/control/deviceinfo
Action:  urn:dslforum-org:service:DeviceInfo:1#GetInfo
→ States: fritzbox.modelName, fritzbox.firmwareVersion
```

#### Host-Count
```
Service: /tr064/upnp/control/hosts
Action:  urn:dslforum-org:service:Hosts:1#GetHostNumberOfEntries
→ Anzahl für Loop
```

#### Host Entry (Loop 0..N-1)
```
Service: /tr064/upnp/control/hosts
Action:  urn:dslforum-org:service:Hosts:1#GetGenericHostEntry
→ States: devices.<MAC>.[name|ip|mac|active|iface]
```

---

## 3. TCP Tunnel Manager-Schnittstelle

### 3.1 Konzept

```
Anderer Adapter          FritzWireguard-Adapter         Zielgerät (entferntes Netz)
     │                          │                               │
     │  TCP connect             │                               │
     ├─────────────────────────►│ net.createServer              │
     │  127.0.0.1:localPort     │      │                        │
     │                          │      │ net.connect            │
     │                          │      ├───────────────────────►│
     │                          │      │  remoteHost:remotePort │
     │◄────────────────────────►│◄─────┼───────────────────────►│
     │  bidirektionaler Pipe    │      │  bidirektionaler Pipe  │
```

### 3.2 Tunnel-Konfigurationsobjekt

```json
{
  "id":         "kostal",
  "name":       "Kostal Piko",
  "localPort":  8085,
  "remoteHost": "192.168.178.55",
  "remotePort": 80,
  "enabled":    true
}
```

### 3.3 TunnelManager Methoden

| Methode          | Beschreibung                                                  |
|------------------|---------------------------------------------------------------|
| `start(t)`       | Öffnet TCP-Server auf `127.0.0.1:t.localPort`                |
| `startAll(list)` | Startet alle `enabled: true` Tunnel                           |
| `stop(id)`       | Schließt Server, löscht Stats                                 |
| `stopAll()`      | Alle Tunnel stoppen                                           |
| `statusAll(cfg)` | Array mit Runtime-Status aller konfigurierten Tunnel          |

### 3.4 Statistiken pro Tunnel

| Feld      | Typ    | Beschreibung                       |
|-----------|--------|------------------------------------|
| `active`  | number | Aktuell offene Verbindungen        |
| `total`   | number | Verbindungen gesamt (seit Start)   |
| `rxBytes` | number | Bytes vom Zielgerät empfangen      |
| `txBytes` | number | Bytes zum Zielgerät gesendet       |
| `error`   | string | Letzter Fehler (null wenn keiner)  |
| `running` | bool   | Server aktiv?                      |

### 3.5 Protokollunterstützung

Da reine TCP-Pipe — alle TCP-basierten Protokolle werden transparent unterstützt:

| Protokoll | typischer Port | Beispiel Adapter      |
|-----------|---------------|-----------------------|
| HTTP      | 80, 8080      | Kostal Piko, Solarlog |
| HTTPS     | 443           | (kein TLS-Termination)|
| Modbus/TCP| 502           | Modbus-Adapter        |
| MQTT      | 1883          | MQTT-Adapter          |
| Custom    | beliebig      | beliebig              |

> **Hinweis:** UDP wird nicht unterstützt. Für UDP-Modbus wäre ein separater Proxy nötig.

---

## 4. REST-API

**Basis:** `http://host:8094/api/`

| Methode | Pfad                    | Beschreibung                                     |
|---------|-------------------------|--------------------------------------------------|
| GET     | `/api/ping`             | Erreichbarkeitstest                              |
| GET     | `/api/status`           | WG + FritzBox + Devices (aus Cache)              |
| GET     | `/api/tunnels`          | Status aller Tunnel mit Statistiken              |
| POST    | `/api/tunnels/restart`  | Alle Tunnel stoppen und neu starten              |
| GET     | `/api/logs`             | Logs (`?n=&level=&category=`)                    |
| GET     | `/api/version`          | Installierte Version                             |
| POST    | `/api/connect`          | WireGuard verbinden                              |
| POST    | `/api/disconnect`       | WireGuard trennen                                |
| POST    | `/api/poll`             | Sofort-Poll (WG + TR-064)                        |

### GET /api/tunnels — Response

```json
[
  {
    "id":         "kostal",
    "name":       "Kostal Piko",
    "localPort":  8085,
    "remoteHost": "192.168.178.55",
    "remotePort": 80,
    "enabled":    true,
    "running":    true,
    "active":     1,
    "total":      42,
    "rxBytes":    204800,
    "txBytes":    81920,
    "error":      null
  }
]
```

---

## 5. ioBroker-Schnittstelle

Verwendet `@iobroker/adapter-core` Methoden:
- `setObjectNotExistsAsync` — State-Objekt anlegen
- `setStateAsync` — State-Wert schreiben
- `log.error / .warn / .debug` — ioBroker-Systemlog

---

## 6. Datenfluss

```
Adapter-Start
  │
  ├─ TunnelManager.startAll()   → lokale Ports auf 127.0.0.1 öffnen
  ├─ HTTP-Server starten
  ├─ _connectWg()               → wg-quick up → VPN-Tunnel aktiv
  │
  └─ _poll() [alle N Sekunden]
        │
        ├─ _pollWg()            → wg show → wireguard.* States
        │
        ├─ [wg connected?]
        │    Ja  → _pollFritzBox()
        │              ├─ SOAP WAN-IP      → fritzbox.externalIP
        │              ├─ SOAP Uptime      → fritzbox.uptime / .connectionType
        │              ├─ SOAP DeviceInfo  → fritzbox.modelName / .firmwareVersion
        │              └─ _pollHosts()
        │                    └─ SOAP GetGenericHostEntry[0..N]
        │                          └─ devices.<MAC>.* States
        │
        └─ Nein → WARN-Log
                  [autoReconnect?] → _connectWg()

Anderer Adapter verbindet 127.0.0.1:8085 (z.B. Kostal)
  │
  └─ TunnelManager Server → net.connect(192.168.178.55:80)
                          → bidirektionaler Pipe über WireGuard-Tunnel
```

---

## 7. Log-Kategorien

| Kategorie | Inhalt                                          |
|-----------|-------------------------------------------------|
| `SYSTEM`  | Start, Stopp, Serverstart                       |
| `WG`      | WireGuard Connect/Disconnect/Sanitize-Warnings  |
| `TR064`   | SOAP-Abfragen (WAN, Status, DeviceInfo)         |
| `HOSTS`   | Host-Listing                                    |
| `TUNNEL`  | Tunnel-Start, neue Verbindungen, Fehler         |
| `POLL`    | Poll-Zyklus Fehler                              |
| `STATE`   | State-Änderungen                                |
