# Übung 5 - Malware Analyse

## Gruppenmitglieder

- Lorenzo Haidinger
- Astrid Kuzma-Kuzniarski
- Philip Magnus

## System Setup

Die Übung wurde auf einem Ubuntu 24.04 LTS Host mit REMnux Gast-System durchgeführt.
REMnux ist eine Sammlung an Softwarepaketen, die eine minimale Ubuntu 20.04 LTS installation erweitern, für Malwareanalyse.
Auf der [REMnux](https://remnux.org/) können verschiedene Möglichkeiten genutzt werden um das System zu beziehen. Für unseren Fall wurde das System wie empfohklen als fertige `.ova` Datei heruntergeladen und in VirtualBox importiert.

Nach dem Import wurde direkt ein Snapshot angelegt um einen funktionierenden Wiederherstellungspunkt zu haben.

![Snapshot](./screenshots/screen_1.png)

Dies ist auch das Vorgehen, wie es in den Slides zur Malwareanalyse als Best-Practices steht.

Die Malwaresamples wurden über einen temporären Filehoster (gofile) auf die VM zur Analyse übertragen und auf der VM entpackt.

![Filetransfer](./screenshots/screen_2.png)

## Information Gathering

### Sample 1

1. Mit `msoffcrypto-crack [Datei]`[¹](https://docs.remnux.org/discover-the-tools/analyze+documents/microsoft+office#msoffcrypto-crack.py) konnten wir das Password vom Sample recovern.

```bash
remnux@remnux:~/workspace/AppSec$ msoffcrypto-crack.py fb5ed444ddc37d748639f624397cff2a.bin 
Password found: VelvetSweatshop
```