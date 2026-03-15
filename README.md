# ioBroker FritzWireguard Adapter

[![Version](https://img.shields.io/badge/version-0.2.1-blue.svg)](https://github.com/MPunktBPunkt/iobroker.fritzwireguard)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen.svg)](https://nodejs.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/MPunktBPunkt/iobroker.fritzwireguard)

Verbindet ioBroker via **WireGuard VPN** mit einer entfernten FritzBox. Der Adapter stellt
Netzwerkgeräte, WAN-Status und FritzBox-Infos als ioBroker-Datenpunkte bereit und ermöglicht
über einen integrierten **TCP Tunnel Manager**, einzelne Adapter selektiv mit Geräten im
entfernten Netz zu verbinden — ohne den restlichen Traffic anderer Adapter zu beeinflussen.

---

## Features

* 🔐 **WireGuard VPN** – automatischer Verbindungsaufbau und -wiederherstellung via `wg-quick`
* 🛡️ **Config-Sanitizer** – entfernt automatisch DNS-Overwrite und Full-Tunnel (`0.0.0.0/0`) aus der WireGuard-Config
* 📡 **TR-064 Integration** – liest WAN-IP, Uptime, Modell, Firmware und alle Netzwerkgeräte
* 🔀 **TCP Tunnel Manager** – leitet einzelne lokale Ports (`127.0.0.1:X`) transparent durch den VPN-Tunnel; alle anderen Adapter bleiben im lokalen Netz
* 🌐 **Web-UI** – Browser-Interface mit Daten-, Nodes-, Tunnel-, Log- und System-Tab
* 📊 **Tunnel-Statistik** – Live-Anzeige von aktiven Verbindungen und Traffic pro Tunnel
* 🔄 **Auto-Reconnect** – erkennt Verbindungsabbrüche und verbindet automatisch neu
* 🗑️ **Sichere Config-Verwaltung** – WG-Config wird als `chmod 600` Datei gespeichert und beim Stopp gelöscht

---

## Voraussetzungen

### Auf dem ioBroker-Host (Linux)

```bash
# WireGuard installieren
sudo apt update && sudo apt install -y wireguard

# sudo-Rechte für iobroker-Benutzer
echo "iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg-quick" \
  | sudo tee /etc/sudoers.d/iobroker-wireguard
echo "iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg" \
  | sudo tee -a /etc/sudoers.d/iobroker-wireguard
sudo chmod 440 /etc/sudoers.d/iobroker-wireguard
```

### FritzBox-Einstellungen

1. **WireGuard VPN aktivieren:** FritzBox Admin → Internet → Freigaben → VPN (WireGuard) → neuen Client anlegen → Config-Datei herunterladen
2. **TR-064 aktivieren:** FritzBox Admin → Heimnetz → Netzwerk → Heimnetzfreigaben → „Zugriff für Anwendungen zulassen" ✅
3. **Benutzer anlegen** mit Recht „FRITZ!Box-Einstellungen" für TR-064-Zugriff

---

## Installation

### Option A – von GitHub

```bash
iobroker add https://github.com/MPunktBPunkt/iobroker.fritzwireguard
```

### Option B – manuell (offline)

```bash
mkdir -p /opt/iobroker/node_modules/iobroker.fritzwireguard
# Dateien kopieren: main.js, io-package.json, package.json, admin/
cd /opt/iobroker/node_modules/iobroker.fritzwireguard
npm install
cd /opt/iobroker
iobroker add fritzwireguard
```

---

## Konfiguration

Nach der Installation im ioBroker Admin → **Adapter → FritzWireguard** → Instanz anlegen:

### Tab: Verbindung

| Einstellung     | Standard        | Beschreibung                             |
|-----------------|-----------------|------------------------------------------|
| FritzBox IP     | `192.168.178.1` | IP der FritzBox im VPN-Netz              |
| TR-064 Port     | `49000`         | TR-064 Port (FritzBox Standard)          |
| Benutzername    | –               | TR-064 Benutzername                      |
| Passwort        | –               | TR-064 Passwort                          |
| Web-UI Port     | `8094`          | Port der Browser-Oberfläche             |
| Poll-Intervall  | `60`            | Abfrage-Intervall in Sekunden (min. 30)  |

### Tab: WireGuard

Vollständigen Inhalt der von der FritzBox exportierten `.conf`-Datei einfügen:

```ini
[Interface]
PrivateKey = <dein-private-key>
Address = 10.8.0.2/32

[Peer]
PublicKey = <public-key-der-fritzbox>
Endpoint = <myfritz-adresse>:<port>
AllowedIPs = 192.168.178.0/24
PersistentKeepalive = 25
```

> **Hinweis:** `DNS =` Zeilen und `0.0.0.0/0` in AllowedIPs werden vom Adapter automatisch
> entfernt, um systemweite DNS-Änderungen und Full-Tunnel zu verhindern.

| Einstellung              | Standard | Beschreibung                           |
|--------------------------|----------|----------------------------------------|
| Automatisch verbinden    | ✅       | VPN beim Adapterstart aufbauen         |
| Auto-Reconnect           | ✅       | Bei Verbindungsverlust neu verbinden   |
| VPN beim Stopp trennen   | ✅       | `wg-quick down` bei Adapter-Stopp      |

### Tab: Port-Tunnel

Hier richtest du TCP-Weiterleitungen ein, um einzelne Adapter mit Geräten im entfernten
Netz zu verbinden, ohne den restlichen Traffic zu beeinflussen.

| Spalte         | Beschreibung                                                  |
|----------------|---------------------------------------------------------------|
| Name           | Bezeichnung des Tunnels (z. B. „Kostal Piko")                 |
| Lokaler Port   | Port auf `127.0.0.1`, den der andere Adapter anspricht        |
| Ziel-IP        | IP des Geräts im entfernten Netz (z. B. `192.168.178.55`)    |
| Ziel-Port      | Port am Zielgerät (z. B. `80` für HTTP, `502` für Modbus)    |
| Aktiv          | Tunnel aktivieren                                             |

**Beispiel: Kostal Piko Wechselrichter im entfernten Netz**

```
Tunnel:       Lokaler Port 8085 → 192.168.178.55:80
Adapter:      Kostal Piko → Host: 127.0.0.1 | Port: 8085
Ergebnis:     Kostal-Adapter erreicht den Wechselrichter über VPN
              Alle anderen Adapter bleiben im lokalen Netz
```

---

## Angelegte Datenpunkte

Unter `fritzwireguard.0`:

```
fritzwireguard.0
  info.connection           – Adapter verbunden (boolean)
  info.lastUpdate           – Letzte Aktualisierung (string, ISO-8601)

  wireguard.status          – "connected" / "disconnected"
  wireguard.handshake       – Zeitpunkt letzter Handshake
  wireguard.rxBytes         – Empfangene Bytes
  wireguard.txBytes         – Gesendete Bytes

  fritzbox.externalIP       – Aktuelle externe IP
  fritzbox.uptime           – Verbindungs-Uptime in Sekunden
  fritzbox.connectionType   – Verbindungsstatus
  fritzbox.modelName        – FritzBox-Modell (z. B. FRITZ!Box 7590)
  fritzbox.firmwareVersion  – Aktuelle Firmware-Version

  devices.AA_BB_CC_DD_EE_FF
    .name    – Hostname
    .ip      – IP-Adresse
    .mac     – MAC-Adresse
    .active  – Aktuell aktiv? (boolean)
    .iface   – Interface-Typ (LAN / 802.11)
```

---

## Web-UI

Im Browser öffnen: `http://<ioBroker-IP>:8094/`

| Tab          | Inhalt                                                              |
|--------------|---------------------------------------------------------------------|
| 📊 Daten     | WireGuard-Status-Badge, Karten mit WG- und FritzBox-Infos          |
| 🔌 Nodes     | Tabelle aller Netzwerkgeräte mit aktivem/inaktivem Status           |
| 🔀 Tunnel    | Konfigurierte TCP-Tunnel mit Verbindungszähler und Traffic-Statistik|
| 📋 Logs      | Echtzeit-Log mit Level-/Kategorie-Filter und Export                 |
| ⚙️ System    | VPN verbinden/trennen, Sofort-Poll, Adapter-Info                    |

---

## REST-API

| Methode | Endpunkt                | Beschreibung                       |
|---------|-------------------------|------------------------------------|
| GET     | `/api/ping`             | Erreichbarkeitstest                |
| GET     | `/api/status`           | Kompletter Status als JSON         |
| GET     | `/api/tunnels`          | Tunnel-Status mit Statistiken      |
| POST    | `/api/tunnels/restart`  | Alle Tunnel neu starten            |
| GET     | `/api/logs`             | Log-Einträge (Filter: level, category, n) |
| GET     | `/api/version`          | Installierte Version               |
| POST    | `/api/connect`          | WireGuard verbinden                |
| POST    | `/api/disconnect`       | WireGuard trennen                  |
| POST    | `/api/poll`             | Sofortige Abfrage auslösen         |

---

## Changelog

### 0.2.1 (2026-03-15)
* **Bugfix:** Absturz der Einstellungsseite beim Eingeben von Benutzername/Passwort behoben
* **Sicherheit:** FritzBox-Passwort und WireGuard-Config werden jetzt verschlüsselt im ioBroker-Store gespeichert (`encryptedNative`)
* **Bugfix:** `this.log` in früher Initialisierungsphase gegen undefined abgesichert

### 0.2.0 (2026-03-14)
* **Neu:** TCP Tunnel Manager — selektive Port-Weiterleitung durch VPN für einzelne Adapter
* **Neu:** Tunnel-Tab in der Web-UI mit Live-Verbindungsstatistik
* **Neu:** Tunnel-Konfiguration als Tabelle im ioBroker Admin (Tab „Port-Tunnel")
* **Neu:** `POST /api/tunnels/restart` Endpunkt
* **Neu:** WireGuard Config-Sanitizer — entfernt automatisch DNS-Zeilen und `0.0.0.0/0`
* **Neu:** Log-Kategorie `TUNNEL`

### 0.1.0 (2026-03-14)
* Erstveröffentlichung
* WireGuard-Verbindungsmanagement via `wg-quick`
* TR-064: WAN-IP, Uptime, Modell, Firmware, Hosts
* Web-UI: Daten / Nodes / Logs / System
* REST-API für Status, Logs und Verbindungssteuerung
* Sichere temporäre Config-Verwaltung (chmod 600, Auto-Delete)

---

## Lizenz

MIT © MPunktBPunkt
