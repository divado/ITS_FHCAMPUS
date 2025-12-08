#set text(size: 11pt)

= Introduction

== Goal of the Assignment

#v(0.5cm)

The exercise consists of setting up a secure HTTPS web server with nginx that exclusively uses modern, strong TLS mechanisms.\
The main goal is to configure the web server so that it achieves the maximum final score of 100 in the security test with testssl.sh.


== Prerequisites

The assignment was completed with the following software and other prerequisites:

- Operating System: Ubuntu 24.04 LTS
- Docker or a Linux-VM with nginx-Installation
- OpenSSL for generating a self-signed certificate

== Assignment Information

#v(0.5cm)

Setzen Sie einen HTTPS Webserver mit nginx auf (z.B. mittels Docker Container).\
Dieser soll ausschließlich TLS 1.2 und TLS 1.3 unterstützen. Self-signed Zertifikate sind ausreichend.\
Testen Sie Ihren Webserver mit testssl.sh (Website, GitHub). testssl.sh führt ein Rating anhand des "SSL Labs's SSL Server Rating Guide" durch (Anm.: testssl.sh wird auch von Ivan Ristic empfohlen).\
Das Ziel dieser Übung ist es, einen "Final Score" von 100 erreichen (= "Flag").\

Dokumentieren Sie in einem Protokoll (PDF) Ihre Vorgangsweise und alle notwendigen Schritte.\

Die Übung haben Sie erfolgreich abgeschlossen, wenn

- 4 Punkte (Ziel): Sie einen "Final Score" von 100 erreichen (="Flag")
  - 2 Punkte: Ihr Webserver ausschließlich TLS 1.2 und TLS 1.3 unterstützt
  - 2 Punkte: TLS Session Tickets #strong[deaktiviert] sind
    - Achtung: wird nicht farblich markiert von testssl.sh
    - Optional: Links für mehr Informationen\ 
        We need to talk about Session Tickets\
        We Really Need to Talk About Session Tickets: A Large-Scale Analysis of Cryptographic Dangers with TLS Session Tickets
  - Sie nur "grüne" Ausgaben von testssl.sh haben, also:
    - 2 Punkte: Keine weak Ciphers unterstützt werden ("not offered")
    - 2 Punkte: Nur "Forward Secrecy strong encryption (AEAD ciphers)" unterstützt werden
    - 2 Punkte: Keine der getesteten Schwachstellen vorhanden sind ("not vulnerable")
    - Ausnahmen:
      - Hinsichtlich (self-signed) Zertifikat: SAN, Trust, OCSP
      - DNS CAA RR
    - Ausführung von testssl.sh mittels (für Akzeptanz von Self-signed Cert): ./testssl.sh --add-ca </path/to/selfsigned.crt> <IP>:<Port>
      - via https://github.com/drwetter/testssl.sh/issues/1700#issuecomment-673520807
- Ihre Vorgehensweise nachvollziehbar dokumentiert haben
- Folgende Dateien in einem .zip-Archiv abgegeben haben:
  - Ihr Protokoll als PDF
  - Ihren private Key,
  - das zugehörige Zertifikat und
  - Ihre (vollständige) finale nginx Config.

#strong[Links/Ressourcen:]

- testssl.sh:
  - https://testssl.sh/
  - https://github.com/drwetter/testssl.sh
    - Für Self-signed Certs: https://github.com/drwetter/testssl.sh/issues/1700#issuecomment-673520807
- "SSL Labs's SSL Server Rating Guide"
- OpenSSL Cookbook (Ivan Ristic)
- Sichere nginx TLS Config:
  - https://cipherlist.eu/
  - https://wiki.mozilla.org/Security/Server_Side_TLS
  - https://ssl-config.mozilla.org/

#pagebreak()