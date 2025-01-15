# Altklausur - NDT

Lösung der Network Defense Technologies Alt-Prüfung, zur Prüfungsvorbereitung.

## Aufgabe 1

![Aufgabe 1](./altklausur/IMG_1193-min.JPG)

**Antwort:**


1. **Confidentiality**
    - **Beschreibung**: durch die Confidentiality soll sichergestellt werden, dass Informationen nur von autorisierten Personen eingesehen werden können.
    - **Angriff**: TCP/IP Traffic ist standardmäßig nicht verschlüsselt. D.h. ein Angreiffer, könnte durch eine MitM (Man in the Middle) Attacke, wenn er on-path des Traffics ist einfach den gesamten Verkehr mitlesen.
    - **Mitigation**: Durch den Einsatz von Verschlüsselungsprotokollen wie z.B. SSL/TLS kann die Confidentiality von Daten bewahrt werden.
2. **Integrity**
    - **Beschreibung**: durch die Integrität soll gewährleister werden, dass Daten genau, vollständig und unverändert bleiben. Informationen sollen sol vor Manipulation geschützt werden.
    - **Angriff**: standardmäßig gibt es keine Möglichkeit zu überprüfen ob eine Nachricht verändert wurde oder nicht, daher kann ein on-path Angreifer Traffic einfach manipulieren. Es existiert zwar eine Checksum, diese ist aber zur Erkennung von Übertragungsfehlern konzipiert nicht für die Erkennung von Manipulationen der übertragenen Informationen.
    - **Mitigation**: Auch hier hilft die Nutzung von TLS. TLS verwendet Message Authentication Codes um die Integerity von übertragenen Informationen zu gewährleisten.
3. **Availability** 
    - **Beschreibung**: durch die Availability sollen Daten und Systeme für Benutzer immer zur verfügung stehen.
    - **Angriff**: Durch eine SYN Flodding Attacke, könnte die Availability eingeschränkt werden. Hier würde durch das wiederholte senden von SYN Anfragen an einen Server dieser durch das Abspeichern der Verbindungen irgendwann keine neuen Verbindungen mehr annehmen können.
    - **Mitigation**: Hier gibt es verschiedene Möglichkeiten, welche am besten in Kombination eingesetzt werden, diese Art von Angriffen zu verhindern. Bspw. die Implementierung von SYN Cookies, Rate Limiting oder auch Load Balancing. Der Einsatz von Firewalls für die Erkennung von bspw verdächtigen Verbindungen und Intrusion Detection Systeme um verdächtigen Traffic zu erkennen und entsprechend zu blockieren

\newpage

## Aufgabe 2

![Aufgabe 2](./altklausur/IMG_1187-min.JPG)

**Antwort:** 

**a)**

_Rules table_

|  #  | Src IP | Src Prt | Dst IP | Dst Prt | Proto |    Action    |
|:---:|:------:|:-------:|:------:|:-------:|:-----:|:------------:|
|  1  |    A   |  ?(*)   |    B   |    22   |  TCP  |  ALLOW       |
|  2  |    B   |   22    |    A   |   ?(*)  |  TCP  |  ALLOW       |
|  3  |    *   |    *    |    *   |    *    |   *   |  DROP/REJECT |

**b)**

_Rules table_ (static, created by admin):

|  #  | Src IP | Src Prt | Dst IP | Dst Prt | Proto |    Action    |
|:---:|:------:|:-------:|:------:|:-------:|:-----:|:------------:|
|  1  |    A   |  ?(*)   |    B   |    22   |  TCP  |    ALLOW     |
|  3  |    *   |    *    |    *   |    *    |   *   |  DROP/REJECT |


_State table_ (dynamically created at runtime by filter):

|  #  | Src IP  | Src Prt  | Dst IP  | Dst Prt  | Proto | Action   |
|:---:|:-------:|:--------:|:-------:|:--------:|:-----:|:--------:|
|  1  |    A    |   23276  |    B    |    22    |  TCP  |  ALLOW   |

\newpage

## Aufgabe 3

![Aufgabe 3](./altklausur/IMG_1188-min.JPG)

**Antwort:**

**a)**

DNS Certification Authority Authorization (CAA) ist ein Sicherheitsmechanismus, der Domainbesitzern die Kontrolle darüber gibt, welche Zertifizierungsstellen (CAs) SSL-Zertifikate für ihre Domains ausstellen dürfen.

CAA wurde entwickelt, um das Risiko einer fehlerhaften oder böswilligen Ausstellung von SSL/TLS-Zertifikaten zu minimieren. Theoretisch könnte jede öffentliche CA Zertifikate für beliebige Domains ausstellen.

Durch die Überprüfung ob eine CA überhaupt berechtigt ist ein Zertifikat auszustellen soll dies verhindert werden. Eine CA muss also erst in einem CAA Record überprüfen ob sie ein Zertifikat für die Domain ausstellen darf.


**b)**

Ein CASB ist ein sogenannter Erzwingungspunkt für die Sicherheitsrichtlinien zwischen Unternehmensbenutzern und Cloud-Dienstanbietern.

Die im CASB umgesetzten Sicherheitsrichlinen sollen vor Datenlecks und bedrohungen schützen indem:

- Authentifizierung und Zugriffskontrolle umgesetzt wird
- Verschlüsselung sensibler Daten
- Erkennung und Blockierung von Malware
- Überwachung und Benutzeraktivitäten

CASBs bieten einen Einblick in die Nutzung von Cloud-Software über diverse Anbieter hinweg und ermöglichen somit:

- Erkennung von Shadow IT
- Überwachung des Datentransfers
- Durchsetzung von Richtlinien


\newpage

## Aufgabe 4

![Aufgabe 4](./altklausur/IMG_1189-min.JPG)

**Antwort:**

**a)**

APTs, oder lang Advanced Persistent Threats, sind komplexe und langanhaltende Cyberangriffe die meistens von gut ausgebildeten und stark finazierten Gruppen ausgehen. Die Angreifer gehen meist über lange Zeiträume vor, mehrere Monate bis teilweise Jahre. Es werden technisch stark fortgeschrittene Techniken verwendet, bspw. Zero-Day Exploits.

Ziele von APTs sind meistens Regierungsorganisationen, große Unternehmen, Infrastruktur oder Forschungseinrichtungen.

**b)**

**Lebenszyklus eines APT-Angriffs:**

1. **Reconnaissance**: Informationen sammeln, z. B. durch OSINT.
2. **Initial Access**: Phishing-E-Mails, Exploits oder
kompromittierte Software.
3. **Persistence**: Backdoors oder Malware
installieren, um dauerhaft Zugriff zu behalten.
4. **Lateral Movement**: Innerhalb des Netzwerks
weitere Systeme kompromittieren.
5. **Data Exfiltration**: Sensible Daten sammeln und abtransportieren.
6. **Cover Tracks**: Logs löschen und Hintertüren tarnen.

\newpage

## Aufgabe 5 (VPN Aufgabe, haben wir nicht gemacht in der VL)

![Aufgabe 5](./altklausur/IMG_1190-min.JPG)

**!ANTWORT WURDE AI GENERIERT WEIL WIR DAS NICHT IN DER VL HATTEN!**

**Antwort:**

**Netzwerkebene**

- IPsec arbeitet auf der Netzwerkebene (Layer 3) und verschlüsselt komplette IP-Pakete
- SSL/TLS operiert auf der Anwendungsebene und verschlüsselt nur den HTTP-Traffic über TCP

**Sicherheitsmerkmale**

- IPsec hat eine kleinere Angriffsfläche, da kritische Sicherheitsfunktionen im Kernel ausgeführt werden1
- IPsec ist resistenter gegen DoS-Angriffe durch die Verarbeitung auf niedrigerer Netzwerkebene
- SSL/TLS ist anfälliger für bekannte Schwachstellen wie POODLE, BEAST oder Heartbleed

**Verbindungsaufbau**

- IPsec-Tunnel können von vielen Verbindungen gleichzeitig genutzt werden
- SSL/TLS erstellt für jede Verbindung einen separaten Tunnel

**Empfohlene Einsatzszenarien**
**IPsec empfohlen für:**

- Site-to-Site VPNs zwischen Unternehmenstandorten
- Hochsichere Umgebungen mit strengen Sicherheitsanforderungen6
- Szenarien mit hohem Durchsatz und geringer Latenz

**SSL/TLS empfohlen für:**

- Remote Access für einzelne Benutzer
- Webbasierte Anwendungen und Dienste
- Situationen, die einfache Implementierung und Wartung erfordern

Die Wahl hängt primär vom Einsatzzweck ab: IPsec für permanente Netzwerkverbindungen mit hohen Sicherheitsanforderungen, SSL/TLS für flexiblen Remote-Zugriff einzelner Nutzer auf spezifische Anwendungen.