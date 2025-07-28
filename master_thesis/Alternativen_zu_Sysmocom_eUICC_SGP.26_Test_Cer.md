<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" class="logo" width="120"/>

# Alternativen zu Sysmocom eUICC mit SGP.26 Test Certificates

Ja, es gibt mehrere Alternativen zum Sysmocom eUICC for consumer eSIM RSP mit SGP.26 Test Certificates für Testzwecke:

## Hardware-Alternativen

### COMPRION Test eUICC - Consumer Device

COMPRION bietet eine Test eUICC speziell für Consumer Devices an[^1]. Diese ist mit Test Certificates und Test Keys nach der GSMA SGP.26 V1.2 - RSP Test Certificates Definition Specification konfiguriert[^1]. Die Karte:

- Unterstützt 1.8V / 3V / 5V
- Arbeitet im Temperaturbereich von -25°C bis +85°C
- Verfügbar im Triple Format (2FF, 3FF, 4FF)
- Ist als repluggable Card ausgelegt[^1]


## Test Profile Services

### Infineon Test SM-DP+ Profile Server

Infineon betreibt einen Test SM-DP+ Profile Server unter `testsmdpplus.infineon.com`, der allerdings eine Login-Wall hat[^2]. Dieser Service unterstützt SGP.26 Test Certificates mit spezifischen Key IDs.

### COMPRION eSIM Test Profile Service

COMPRION bietet ebenfalls einen eSIM Test Profile Service an, dieser ist jedoch kostenpflichtig[^2].

## Modulare Test-Lösungen

### COMPRION RSP M2M Test Platform

COMPRION hat eine **flexible Plattform für erweiterte Tests von M2M Remote SIM Provisioning (RSP) Szenarien** entwickelt[^3]. Die modulare Struktur erlaubt es:

- Reale oder simulierte Back-End Server zu verwenden
- Verschiedene Netzwerkkomponenten zu simulieren
- Tests sowohl in M2M- als auch Consumer Device-Umgebungen durchzuführen[^3]


### COMPRION Network Bridge

Eine **schlanke Software-Lösung für Tests der Remote Provisioning-Fähigkeiten** von nicht gelöteten eUICCs[^3]. Diese Software:

- Stellt direkte Verbindungen zwischen eUICCs und Back-End Servern her
- Enthält Simulationen der wesentlichen Netzwerkkomponenten
- Ermöglicht End-to-End Tests in einem einfachen Setup[^3]


## GSMA Standard Test Profile

### Generic eUICC Test Profile

Die GSMA bietet einen **Generic eUICC Test Profile for Device Testing** als öffentliche Ressource an[^4]. Diese Profile sind:

- Konform mit der SIMalliance Interoperable Profile v2.1
- Verfügbar in verschiedenen Versionen (v1A und v1B)
- Kostenlos für Dritte zur internen Nutzung verfügbar[^4]


## Fazit

Die **COMPRION Test eUICC** scheint die direkteste Hardware-Alternative zu sein, da sie ähnliche SGP.26 Test Certificate-Funktionalität bietet[^1]. Für umfassendere Testszenarien bieten die **modularen COMPRION-Lösungen** mehr Flexibilität bei der Simulation verschiedener RSP-Komponenten[^3]. Die **GSMA Generic Test Profiles** sind eine kostenlose Option für grundlegende Gerätetests[^4].

<div style="text-align: center">⁂</div>

[^1]: https://www.comprion.com/shop/test-euicc-consumer-device.html

[^2]: https://euicc-manual.osmocom.org/docs/rsp/known-test-profile/

[^3]: https://www.comprion.com/testability/news-detail/testing-the-euicc-environment-with-comprion/

[^4]: https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public

[^5]: https://onomondo.com/blog/multi-imsi-vs-esim-vs-uicc/

[^6]: https://www.gsma.com/get-involved/working-groups/wp-content/uploads/2024/07/TS.48-v5.0-Generic-eUICC-Test-Profile-for-Device-Testing.docx

[^7]: https://discourse.osmocom.org/t/easyeuicc-download-sgp-26-test-esims-via-an-android-gui-program/286

[^8]: https://test.rsp.sysmocom.de

[^9]: https://discourse.osmocom.org/t/about-esim-cards/80

[^10]: https://www.1nce.com/en-eu/euicc-sim-card-for-iot-esim/use-cases-how-euicc-capable-sim-cards-help-to-overcome-iot-connectivity-challenges

[^11]: https://www.linkedin.com/posts/sysmocom-systems-for-mobile-communications-gmbh_euicc-for-consumer-esim-rsp-with-sgp26-test-activity-7221214817129238528-ebjz

[^12]: https://shop.sysmocom.de/sysmoEUICC1-eUICC-for-consumer-eSIM-RSP/sysmoEUICC1-C2G

[^13]: https://www.appluslaboratories.cn/cn/en/news/applus+-laboratories-to-evaluate-esim-security-under-gsma-scheme-

[^14]: https://sysmocom.de/news/index.html

[^15]: https://kigen.com/wp-content/uploads/2020/11/Kigen-An-essential-guide-to-GSMA-eSIM-certification.pdf

[^16]: https://github.com/srsran/srsRAN_Project/discussions/323

[^17]: https://www.zipitwireless.com/oem-guide-esims

[^18]: https://shop.sysmocom.de/eUICC-for-consumer-eSIM-RSP-with-SGP.26-Test-Certificates/sysmoEUICC1-C2T

[^19]: https://www.reddit.com/r/NoContract/comments/1h3yo1e/physical_sim_to_esim_adapters_any_that_i_missed/

[^20]: https://trustedconnectivityalliance.org/wp-content/uploads/2022/04/TCA_INTEGRATED-SIM_WHITEPAPER_FINAL.pdf

