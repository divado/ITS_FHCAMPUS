# Übung 5 - Malware Analyse

## Gruppenmitglieder

- Lorenzo Haidinger
- Astrid Kuzma-Kuzniarski
- Philip Magnus

## System Setup

Die Übung wurde auf einem REMnux System durchgeführt. REMnux ist eine Sammlung an Softwarepaketen, die eine minimale Ubuntu 20.04 LTS installation erweitern, für Malwareanalyse.
Auf der [REMnux](https://remnux.org/) können verschiedene Möglichkeiten genutzt werden um das System zu beziehen. Für unseren Fall wurde das System von Hand auf einer minimalen Ubuntu Installation
aufgesetzt, da die Konvertierung des bereitgestellten `OVA` Images zu einem `qcow2` Image leider nicht funktionierte.

Das Ubuntu Basissystem wurde mit von einer Ubuntu [`minimal.iso`](https://releases.ubuntu.com/focal/) installiert, hierfür wurden einfach die Schritte im Installationsassistenten ausgeführt.
Der VM wurden 4 CPU Kerne, 8GB RAM sowie eine 64GB virtuelle Festplatte zugewiesen.

Nach der Installation des Basissystems wurde mit folgenden Befehlen das _REMnux_ Installationsskript heruntergeladen und in den nötigen Ordner gelegt.

```bash
remnux@REMnux~$ wget https://REMnux.org/remnux-cli

remnux@REMnux~$ sha256sum remnux-cli

c8c6d6830cfeb48c9ada2b49c76523c8637d95dc41d00aac345282fb47021f8e remnux-cli

remnux@REMnux~$ mv remnux-cli remnux
remnux@REMnux~$ chmod +x remnux
remnux@REMnux~$ sudo mv remnux /usr/local/bin 
```

Anschließend wurden die für das Skript benötigten Abhängigkeiten installiert.

```bash
remnux@REMnux~$ sudo apt update
remnux@REMnux~$ sudo apt install gnupg curl -y
```
Schließlich konnte die Installation von _REMnux__ gestartet werden.

```bash
remnux@REMnux~$ sudo remnux install
```