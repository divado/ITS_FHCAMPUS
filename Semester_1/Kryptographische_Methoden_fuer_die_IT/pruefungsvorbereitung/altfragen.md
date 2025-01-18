# Altfragen - Kryptographische Methoden für die IT

## Aufgabe 1

<span style="color:red">

<b>Frage:</b><br><br>
a) <br>
Erklären Sie das Konzepot der Plausible Deniability.
<br> <br>
b) <br>
Erklären Sie, wiesofür die Existenz eines Hidden Volume in VeraCrypt Plausible Deniability gilt.
<br> <br>
c)<br>
Sie möchten einige vertrauliche Daten verschlüsselt in einem Clouddienst (z.B. DropBox) ablegen. Sie können entweder ein Stacked Filesystem einsetzen oder eine Veracrypt Containerdatei synchronisieren.
Für welche Variante entscheiden Sie sich? Begründen Sie Ihre Antwort.
Geben Sie außerdem ein Argument an, dass für die andere Variante sprechen würde.

</span>

<br>

**Antwort:**

a) <br>
Plausible Deniability, ist eine steganographische Technik, die es ermöglicht die Existenz von verschlüsselten Dateien oder Nachrichten abgestritten werden kann. Ein Angreifer kann die existenz dieser Nachrichten/Dateien in einem Strom aus Daten, welche wie Zufallsdaten aussehen, nicht beweisen. Die Existenz dieser ist also plausibel abstreitbar.
<br>

b) <br>
Im Kontext von VeraCrypt, bedeutet die Plausible Deniability, dass die Existenz eines Hidden-VeraCrypt-Volume nicht bewiesen werden kann. Bei VeraCrypt kann in einem verschlüsselten Volumen noch ein weiteres Hidden Volume angelegt werden. Das Hidden Volume wird nur entschlüsselt, wenn bei der Einbindung des VeraCrypt Volumes das korrekte Passwort angegeben wird. Die VeraCrypt Datei sieht verschlüsselt aus wie Zufallsdaten aus denen sich die Existenz eines hidden Volumen nicht ableiten lässt. Ein Hidden Volume kann also existieren oder nicht, die Existenz kann also plausibel abgestritten werden, vor allem da sich das Outer Volume auch normal entschlüsseln lässt und Daten enthalten kann.

![VeraCrypt File](./screenshots/veracrypt_volume.png)

![VeraCrypt Mounting](./screenshots/veracrypt_mounting.png)
<br>

c) <br>
Um Dateien verschlüsselt in einem Cloudstorage abzulegen, würde ich ein Stacked Filesystem verwenden.
Mit dem Stacked Filesystem ist es egal, dass man keinen Zugriff auf das unterliegende Blockdevice hat. Benuzter können außerdem,
unabhängig von Adminrechten die Verschlüsselung nutzen und es ist keine a priori Speicherzuweisung notwendig. Außerdem muss nicht wie bei einem VeraCrypt Volume bei jedem Hinzufügen/Entfernen von Dateien
das ganze Volumen im Cloudstorage ausgetauscht werden.

Der Vorteil eines VeraCrypt Volumes wäre aber die umfassende Verschlüsselung, auch von Metadaten und angelegter Dateistruktur. Eventuell könnte die Einbindung des Volumens, nach der Entschlüsselung, in das Betriebssystem auch einen Performancevorteil brinden. Gegenüber der einfacheren Verwendung, erscheinen diese Vorteile aber evtl. marginal.

## Aufgabe 2

<span style="color:red">

<b>Frage:</b><br>
Sie befinden sich in einem öffentlichen WLAN und möchten eine E-Mail an jane.doe@gmail.com verschicken. Aus Compliancegründen ist es notwendig, dass es keinem Google Mitarbeiter möglich ist, den Inhalt der Nachricht zu lesen. 
Geben Sie für jeden der folgende Ansätze an, ob er geeignet ist, dieses Ziel zu erreichen, und begründen Sie jeweils Ihre Antwort.
<br><br>

1. S/MIME Verschlüsselung
2. S/MIME Signatur
3. TLS verschlüsselter SMTP Versand
4. Veracrypt

</span>

<br>

**Antwort:**

1. S/MIME Verschlüsselung ist geeignet um Verschlüsselte Mails zu versenden. Die Mails werden auf Basis von x509 Zertifikaten verschlüsselt, diese müssen vorher von einer CA ausgestellt werden.

2. S/MIME Signatur ist nicht geeignet, wie der Name schon sagt handelt es sich hierbei nur um eine Signatur, also die Bestätigung, dass der Sender über ein passendes Zertifikat verfügt. Der Inhalt der Mail wäre nach wie vor lesbar.

3. TLS verschlüsselter SMTP Versand wäre nicht geeignet. Die Mail wäre nicht Ende-zu-Ende verschlüsselt sondern nur der Weg vom MUA zum MSA. Es handelt sich nur um eine Transportverschlüsselung, d.h. jeder MTA auf dem Weg den die Mail nimmt könnte diese potentiell lesen.

4. VeraCrypt ist ein Spezialfall. Man müsste sich im vorhinein mit dem Empfänger auf einen gemeinsamen Key zum entschlüsseln des Volumes einigen und in dem Volume dann eine Text Datei versenden. Außerdem muss beachtet werden, dass sich das versendete Volume aufgrund seiner Größe überhaupt noch versenden lässt. Hat man sich im vorhinein auf einen Key geeinigt und das Volume ist nicht zu große könnte man so kommunizieren, der Aufwand wäre aber sehr groß und nur geeignet wenn man bereits über einen anderen sicheren Kanal kommuniziert hat.

## Aufgabe 3

<span style="color:red">
<b>Frage:</b><br>
<br>

a) <br>
Nennen Sie 6 Elemente die sich in einem X.509v3 Zertifikat befinden können.
<br>

b) <br>
Sie sehen im Folgenden die openssl Ausgabe des Inhaltes einer CRL. Beantworten Sie zu dieser die folgenden Fragen:	

1. Welche Seriennummer hat die CRL?
2. Welches Subject hat das Zertifikat der Entität, die die CRL ausgestellt hat?
3. Welches kryptographische Verfahren verwendet der Public Key der Entität, welches die CRL ausgestellt hat?
4. Welche Zertifikate mussten aus Sicherheitsgründen widerrufen werden? (Geben Sie die Seriennummer an bzw. markieren Sie die entsprechenden Zertifikate)

Hinweis: Möglicherweise sind nicht alle Antworten aus der Angabe beantwortbar. Geben Sie das in diesem Falle explizit an.

</span>

<br>

```
1 Certificate Revocation List (CRL):
2        Version 2 (0x1)
3     Signature Algorithm: sha256WithRSAEncryption
4        Issuer: /C=US/L=Redmond/O=Microsoft Corporation /CN=Microsoft IT TLS CA 1
5        Last Update: Mar 3 21:34:17 2019 GMT
6        Next Update: Mar 11 21:54:17 2019 GMT
7        CRL extensions:
8            X509v3 Authority Key Identifier:
9               keyid: 58:88:9F:D6:DC:9C:48:22:B7:14:3E:FF:84:88:E8:E6:85:FF:FA:7D
10           1.3.6.1.4.1.311.21.1:
11              [...] 
12           X509v3 CRL Number:
13              173
14           1.3.6.1.4.1.311.21.4:
15              190307214417Z
16 Revoked Certificates:
17    Serial Number: 5475D86F35CC50754549
18       Revocation Date: Sep 23 00:49:00 2017 GMT
19       CRL entry extensions:
20           X509v3 CRL Reason Code:
21              Cessation Of Operation
22    Serial Number: 4FF4BFE3D22D89C6B4F7
23       Revocation Date: Sep 18 11:16:37 2017 GMT
24       CRL entry extensions:
25           X509v3 CRL Reason Code:
26              Superseded
27    Serial Number: 4C610B09680BE197D87C
28       Revocation Date: Sep 12 23:05:23 2017 GMT
29       CRL entry extensions:
30           X509v3 CRL Reason Code:
31              Affiliation Changed
32    Serial Number: 32353D9CAA402807A605
33       Revocation Date: Aug 24 03:28:57 2017 GMT
34       CRL entry extensions:
35           X509v3 CRL Reason Code:
36              Key Compromise
37    Serial Number: 323479639E0E8078AC7A
38       Revocation Date: Aug 24 03:28:57 2017 GMT
39       CRL entry extensions:
40           X509v3 CRL Reason Code:
41              Key Compromise
42    Signature Algorithm: sha256WithRSAEncryption
43       89:d0:bb:cf:a0:2b:ab:9c:16:c8:10:ef:c8:01:f5:0f:78:f0:
44       f2:a5:ed:5c:68:6b:8f:d3:78:7c:b5:24:7b:45:86:2c:15:7d:
45       [...]
46       ee:a4:e9:3f:22:c1:84:e6:85:7a:26:bb:48:46:3e:a1:29:58:
47       df:12:73:cc:65:17:cb:0a
```

<br>

**Antwort:**

