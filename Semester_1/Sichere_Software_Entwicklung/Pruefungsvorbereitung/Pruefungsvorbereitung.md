# Prüfungsvorbereitung

## Altfragen

### Aufgabe 1 

a) Erklären Sie die Programmiersünde _Format String Problems_ (Bug). Bei welcher Art von Befehlen tritt diese auf?

Ein Format String Bug wird durch die falsche Verwendung von Format String Funktionen verrursacht. Wenn im Code Format String Funktionen verwendet werden um nicht vertrauenswürdige Benutzereingaben zu formatieren, kann es bei falscher Nutzung dieser Funktion einem Nutzer möglich sein, durch die Verwendung von Format String Specifiern als Eingabe, beliebige Daten aus dem Programmspeicher auszulesen und evtl. sogar in diesen zu schreiben.

b) Geben Sie ein Beispiel in Codeform für ein _Format String_ Bug an.

Ein Beispiel wäre in C/C++:

```C 
printf(userInput);
```

UserInput ist hier eine beliebige und ungeprüfte Eingabe durch einen Benutzer.


c) Welche Konsequenzen kann ein _Format String_ Bug haben? Nennen Sie mögliche Gegenmaßnahmen.

Ein Format String Bug kann weitreichende Konsequenzen haben. Ein Nutzer könnte beliebige Daten aus dem Programmspeicher auslesen und diesen evtl. sogar schreiben. Hierdurch können andere Fehler provoziert werden, z.B. Buffer Overflows, oder Injection Schwachstellen, wie z.B. SQL Injections, ausgentzt werden.

Mögliche Gegenmaßnahmen:

- Validieren der Benutzereingaben, z.B. durch Whitelisting
- Korrekte Verwendung von Format String Funktionen mit den entsprechenden Specifiern, z.B.:
  - `printf("%s", userInput);`

---

### Aufgabe 2 

Betrachten Sie den folgenden Source Code:

```C 
#include <stdio.h>  
#include <string.h>  

int main(int argc, char* argv[]) {  
  char input[50];  
  int input_lgth = strlen(argv[1]);  
  int copy_lgth;  

  if (input_lgth > 50) {  
      copy_lgth = 50;  
    } else {  
      copy_lgth = input_lgth + 1;  
    }
    
    strncpy(input, argv[1], copy_lgth);  

    printf("%s", input);  
    return 0;  
}  
```
a) Welche Sünde verbirgt sich in diesem Beispiel? Wo befindet sich diese? Gibt es Programmiersprachen, die nicht betroffen sind? Wenn ja, welche?

Die Sünde ist ein Buffer Overflow, wenn die Eingabe genau eine Länge von 50 hat. Die copy_lgth wird dann auf 51 gesetzt und kopiert in den Speicher mit einem Zeichen zu viel. Bei einer Länge von genau 50 würde strncpy() auch den Puffer voll schreiben, und keinen Null-Terminator hinzufügen, was zu unerwartetem Verhalten führen kann. Programmiersprachen mit automatischer Speicherverwaltung und sicheren String-Funktionen wären von Buffer Overflows eher nicht betroffen, aber auch hier lässt es sich nicht ganz ausschließen. (z.B. Java, Python)

b) Welche Konsequenzen verursacht diese Sünde? Geben Sie 2 konkrete Auswirkungen an.

Ein Buffer Overflow überschreibt den benachbarten Speichern und die darin enthaltenen Daten. Dies kann entweder zu einem Absturz des Programms (Denial of Service) führen oder in Extremfällen einem Angreifer ermöglichen arbiträre Daten in den Speicher zu schreiben und so den Programmfluss zu ändern (\[Remote\] Code Execution).

c) Wie kann diese verhindert werden? Korrigieren Sie den betreffenden Code Abschnitt.

```C
#include <stdio.h>  
#include <string.h>  

int main(int argc, char* argv[]) {  
  int input_lgth = strlen(argv[1]);
  char input[input_lgth];  
    
  strncpy(input, argv[1], input_lgth);

  printf("%s", input);  
  return 0;  
}  
```

---

### Aufgabe 3 

a) Erklären Sie im Kontext von Git die Begriffe **Branches** und **Merge**.

1. **Branches** Ein Branch ist eine historische Abfolge von Commits in einem Git Repository. Z.B. der Main Branch, develop Branch und die hiervon abzweigenden feature Branches.

Aus der offiziellen Git Doku -> "Ein beweglicher Pointer auf einen Commit."

2. **Merge** ein Merge bezeichnet eine Zusammenführung von zwei Branches. Wenn zwei Branches nach einer voneinander unabhängigen Entwicklung wieder zusammengeführt werden spricht man von einem Merge.

b) Im folgenden sehen Sie einen Ausschnitt aus einer mit git-flow erstellten git History. Ordnen Sie den Farben den zugehörigen Branch Typ zu.

![git-flow](./screenshots/02%20Feature%20branches.svg)

- Der Vollständigkeit halber eine gute Ressource zum lernen von git-flow: [Atlassian](https://www.atlassian.com/de/git/tutorials/comparing-workflows/gitflow-workflow)

c) Wie wird die Integrity in einem Git-Repository gewährleistet?

Jeder Commit, sowie jedes File wird in Git mit einer Checksum durch SHA1 gekennzeichnet und gespeichert. Eine Änderung an einem Commit hätte so auch eine Änderung des Commit-Hashes zur folge.

---

### Aufgabe 4 

Die folgenden Fragen zielen auf das Security-Modell in Webbrowsern ab.

a) Nehmen wir an, in einem Webbrowser sind zwei Tabs offen. In einem steht in der Adressleiste `https://example.com:443/dir1/index.html`, und in der Adressleiste des anderen Tabs steht `https://www.example.com/dir2/other.html`. Werden die beiden Seiten als derselbe _Origin_ betrachtet?

Nein es handelt sich nicht um den gleichen _Origin_, da die Subdomains verscheiden sind.

Quelle: [web.dev](https://web.dev/articles/same-site-same-origin)

b) Beschreiben Sie den Unterschied zwischen implizierter und expliziter Authentifizierung bei Webapplikationen.

Explizite Authentifizirung bedarf direkter Benutzer Interaktion z.B. durch die Eingabe von Credentials und oder MFA. 
Implizite Authentifizierung findet ohne Interaktion statt, z.B. durch OAuth oder Session Cookies.

c) Was bewirkt die Same-Origin Policy?

- Dass beim Aufruf von Ressourcen fremder Seiten die HTTP-Antwort nicht z.B. per JavaScript wörtlich gelesen werden darf.
  - [x] Wahr 
  - [ ] Falsch 
- Das innerhalb einer Seite (Origin) clientseitig keinerlei HTTP-Requests zu fremden Seiten gesendet werden können.
  - [ ] Wahr 
  - [x] Falsch 
- Das Webseiten keinerlei Ressourcen (JavaScript, CSS, etc.) von fremden Domänen einbinden dürfen.
  - [ ] Wahr 
  - [x] Falsch 
- Das _Cross-Site Request Forgery_-Angriffe vollständig verhindert werden.
  - [ ] Wahr 
  - [x] Falsch

 Quelle: [Mozilla-DN](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)

 ---
  
### Aufgabe 5 

a) Was ist der Unterschied zwischen Authentifizierung und Autorisierung?

Authentifizierung identifiziert mich gegenüber einem System/einer Anwendung, z.B. durch einen Login.
Durch Autorisierung lässt sich prüfen welche Rechte ich in einem/r System/Anwendung habe.

Man könnte sagen, dass wenn man sich gegenüber einem System authentifiziert hat, mit der Identität eine gewisse Autorisierung im System einhergeht.

b) Was können Sie bei er Entwickliung einer Webapplikation gegen das Problem "unsichere direkte Objektreferenzen" tun? Es gibt genau eine richtige Antwort.

- Die zugehörigkeit des aufgerufenen Objektes zum/zur aktuell angemeldeten Benutzer*In überprüfen.
  - [x] Wahr 
  - [ ] Falsch
- Bei jeder Anfrage überprüfen, ob das aktuelle Konto die entsprechende Rolle hat, um die Funktion aufzurufen.
  - [ ] Wahr 
  - [x] Falsch 
- TLS für die Transportverschlüsselung einsetzen.
  - [ ] Wahr 
  - [x] Falsch 
- Aufsteigende Objekt-IDs verwenden.
  - [ ] Wahr
  - [x] Falsch 

---

### Aufgabe 6

Welcher ist der Unterschied zwischen den Maßnahmen gegen Reflected Cross-Site Scripting und Stored Cross-Site Scripting?

- Bei Stored XSS passiert die Ausgabekodierung in der Datenbank, bei Reflected XSS bei der Ausgabe
  - [ ] Wahr
  - [x] Falsch
- Bei Stored XSS ist die Ausgbaenkodierung unabhängig vom jeweiligen Ausgabekontext.
  - [ ] Wahr
  - [x] Falsch
- Es gibt keinen grundsätzlichen Unterschied
  - [x] Wahr
  - [ ] Falsch
- Whitelisting von Eingabeparametern ist bei Stored XSS wirkungslos
  - [ ] Wahr
  - [x] Falsch

> Ich bin mir hier nicht sicher, in einer Altprüfung gab dies volle Punktzahl, allerdings könnte man argumentieren, dass die Eingaben, welche in einer DB (Stored XSS) gespeichert werden, evtl. einen extra Sanitization Schritt durchlaufen müssen.

---

### Aufgabe 7

a) Wie funktionieren, generisch gesprochen, Injection-Angriffe, und zwar unabhängig von der Technologie (SQL, SMTP, LDAP, etc.)?

Bei Injection Angriffen, wird schädlicher Code durch speziell zugeschnittene Eingaben in den auszuführenden Code eingeschleust um diesen vom System ausführen zu lassen. Gemein haben diese Angriffe, dass Benutzereingaben vom System verarbeitet werden indem sie direkt in die/den Query/Befehl eingebunden werden ohne diese zu prüfen oder zu isolieren.

b) Nehmen wir an, es gebe eine OS-Command-Injection-Lücke in einer Webapplikation, die erfolgreich ausgenützt wird. Im Kontext welches Betriebssytembenutzers werden die injizierten Kommandos allgemein gesprochen ausgeführt?

- Mit dem root-Benutzer
  - [ ] Wahr
  - [x] Falsch
- Als privelegierter Betriebssystembenutzer
  - [ ] Wahr
  - [x] Falsch
- Als jender Benutzer, unter dem der Webserver bzw. Applikationsserver läuft.
  - [x] Wahr
  - [ ] Falsch
- Als nichtprevilegierter Benutzer
  - [ ] Wahr
  - [x] Falsch

---

### Aufgabe 8

Wann liegt eine Race Condition vor?

Eine Race-Condition tritt auf, wenn zwei oder mehrere Prozesse/Threads auf eine geteilte Resource zugreifen wollen und die weitere korrekte Ausführung der Anwendung von der Reihenfolge der Zugriffe auf diese Ressource abhängig ist. Bei unzureichender Synchronisation führt dies zu unvorhergesehenen Ergebnissen.

---

### Aufgabe 9

Betrachten Sie folgenden Source Code:

```php
function persistLogin($username, $password) {
  $data = array("username" => $username, "password" => $password);
  setcookie("userdata", $data);
}
```

a) Welche Sünde verbrigt sich in diesem Beispiel? Erläutern Sie das vorliegende Problem im Detail.

**Begangene Sünde**:

Die Funktion speichert das Passwort im Klartext in einem Cookie und verwendet zudem eine falsche Datentypenverarbeitung.

Es handelt sich also um: _Failure to protect stored data_.

**Probleme im Detail**:

Passwort im Klartext: Das Passwort wird unverschlüsselt im Cookie userdate gespeichert. Cookies sind clientseitig und können leicht ausgelesen, manipuliert oder gestohlen werden (z. B. via XSS-Angriffen).

b) Welche Konsequenzen verursacht diese Sünde?

  - Passwort-Exposition: Das Klartext-Passwort ist im Cookie lesbar. Angreifer können es über XSS, Netzwerk-Mitschnitte oder Client-Zugriff stehlen.

  - Account-Übernahme: Mit dem Passwort kann sich ein Angreifer direkt beim Login-System anmelden.

  - Rechtsverstöße: Die Speicherung von Passwörtern im Klartext verstößt gegen Datenschutzbestimmungen (z. B. GDPR, BSI-Empfehlungen).

c) Wie kann diese verhindert werden?

  - **Passwörter niemals im Cookie speichern**
    - Passwörter gehören nicht in Cookies – weder im Klartext noch gehasht.
  - **Sichere „Remember Me“-Funktion implementieren**
    - Generiere ein zufälliges Token (z. B. mit random_bytes), speichere es gehasht in der Datenbank und setze das ungeshashte Token im Cookie:

```php
# AI GENERATED! DO NOT TAKE AT FACE VALUE
function persistLogin($username) {
    $token = bin2hex(random_bytes(32)); // Zufälliges Token
    $hashedToken = hash('sha256', $token);
    // Speichere $hashedToken in der DB (z. B. verknüpft mit $username)
    setcookie("remember_token", $token, [
        'expires' => time() + 86400 * 30, // 30 Tage Gültigkeit
        'secure' => true,    // Nur über HTTPS
        'httponly' => true,  // Kein JavaScript-Zugriff
        'samesite' => 'Strict'
    ]);
}
```
  - **Sessions statt Cookies für Logins verwenden**
    - Nutze serverseitige Sessions ($_SESSION) für die Authentifizierung.
  - **Cookie-Sicherheitsflags setzen**
    - Immer secure, httponly und samesite verwenden, um Cookie-Diebstahl zu erschweren.

---

### Aufgabe 10

a) Gitflow Best Practices - bitte vervollständigen Sie folgende Aussagen:

1. Ein _develop_ Branch wird aus dem **_main_** Branch erstellt.

2. Ein _release_ Branch wird aus dem **_develop_** Branch erstellt.

3. Ein _feature_ Branch wird aus dem **_develop_** Branch erstellt.

b) Wie wird die Integrity in einem Git-Repository gewährleistet?

Siehe Antwort [Aufgabe 3](#aufgabe-3).

---

### Aufgabe 11

Was ist hinsichtlich Updates zu beachten? Nennen Sie 5 Dinge, die vermieden werden sollen und erläutern Sie diese kurz.

**Haben wir nicht wirklich gemacht, darum hier AI generierte Antwort**

Bei der Durchführung von Updates sind folgende **5 Fehler zu vermeiden**, um Sicherheit, Stabilität und Funktionalität zu gewährleisten:

---

### 1. Ungeprüfte Updates im Live-System einspielen  
- **Was zu vermeiden ist**:  
  Updates direkt in der Produktivumgebung ohne vorherige Tests durchführen.  
- **Warum**:  
  Ungetestete Updates können Fehler enthalten, die zu **Ausfallzeiten**, Datenverlust oder Sicherheitslücken führen.  
- **Beispiel**:  
  Ein fehlerhaftes Datenbank-Update könnte kritische Transaktionen blockieren.  

---

### 2. Kompatibilität ignorieren  
- **Was zu vermeiden ist**:  
  Updates installieren, ohne zu prüfen, ob sie mit bestehender Hardware/Software kompatibel sind.  
- **Warum**:  
  Inkompatible Updates können **Systemabstürze** oder Funktionsverluste auslösen (z. B. Treiber, die nicht mit älterer Hardware funktionieren).  
- **Beispiel**:  
  Ein neues Betriebssystem-Update unterstützt keine Legacy-Anwendungen mehr.  

---

### 3. Backups vor dem Update vernachlässigen  
- **Was zu vermeiden ist**:  
  Kein Backup von Daten, Konfigurationen oder Systemzuständen erstellen.  
- **Warum**:  
  Bei fehlgeschlagenen Updates gibt es **keine Rollback-Möglichkeit**, um den vorherigen Zustand wiederherzustellen.  
- **Beispiel**:  
  Ein beschädigtes Firmware-Update macht ein IoT-Gerät unbrauchbar – ohne Backup ist keine Reparatur möglich.  

---

### 4. Sicherheitsupdates verzögern 
- **Was zu vermeiden ist**:  
  Kritische Sicherheits-Patches aufschieben.  
- **Warum**:  
  Bekannte Schwachstellen bleiben ungeschlossen, was **Angriffe wie RCE (Remote Code Execution)** ermöglicht.  
- **Beispiel**:  
  Die Verzögerung eines Patches für eine Zero-Day-Lücke in einer Webanwendung führt zu einem Datenleck.  

---

### 5. Automatische Updates ohne Kontrolle
- **Was zu vermeiden ist**:  
  Updates vollständig automatisieren, ohne manuelle Überprüfung oder Staging-Phasen.  
- **Warum**:  
  Automatisierte Systeme könnten **instabile Beta-Versionen** einspielen oder Updates zur falschen Zeit durchführen (z. B. während Spitzenlastzeiten).  
- **Beispiel**:  
  Ein automatisches Update einer E-Commerce-Plattform während des Black Friday führt zum Ausfall des Shops.  

---

### Zusammenfassung  
- Testen Sie Updates **immer in einer Staging-Umgebung**.  
- Prüfen Sie **Kompatibilität** mit bestehender Infrastruktur.  
- Erstellen Sie **Backups** vor jedem Update.  
- Priorisieren Sie **Sicherheitsupdates** zeitnah.  
- Nutzen Sie **kontrollierte Automatisierung** (z. B. mit Approval-Workflows).  

Durch das Vermeiden dieser Fehler minimieren Sie Risiken und stellen sicher, dass Updates reibungslos und sicher ablaufen. 🔄🔒

---

## Sünden

### Format String Problems and Command Injection

#### Format String Problems

  - Fehlerhafte Verwendung von Format-Strings, die Angreifern Zugriff auf Speicher oder Kontrolle über Programme ermöglichen.
  - Benutzereingaben werden als Format-String interpretiert

**Mitigation**:
  - Feste Format-Strings verwenden
  - Eingaben validieren (Whitelist-Ansatz)

#### Command Injection

  - Angriffe, bei denen ein Angreifer eigene Befehle in Systemkommandos einschleust.

**Mitigation**:
  - Parameterisierte Befehle verwenden
  - Eingaben vor der Nutzung strikt bereinigen

### Buffer and Integer Overflows

#### Buffer Overflows 

Ein Buffer ist ein temporärer Speicherbereich, in dem Programme Daten ablegen, um sie
schnell zu verarbeiten. Ein Buffer Overflow tritt auf, wenn ein Programm mehr Daten in
diesen Speicherbereich schreibt, als dessen Kapazität erlaubt. Dies führt dazu, dass die
überschüssigen Daten benachbarte Speicherbereiche überschreiben können.
Um einen Buffer Overflow gezielt auszunutzen, können Angreifer schädlichen Code in
den Speicher einschleusen und gleichzeitig die Rücksprungadresse (Return Address)
manipulieren. Dadurch wird das Programm dazu gebracht, diesen Schadcode
auszuführen.

**Mitigation:**

**1. Prävention** 

- Kompilierwarnungen nutzen
  - Viele moderne Compiler, wie GCC oder Clang, können potenziell unsicheren Code erkennen und Warnungen ausgeben, wenn beispielsweise gefährliche Funktionen verwendet oder die PuƯergrößen nicht korrekt berücksichtigt werden. Aktivierung von Optionen wie -Wall oder -Wextra kann helfen, potenzielle Schwachstellen frühzeitig zu identifizieren.
- Sichere String-Verarbeitung
  - Unsichere Funktionen wie gets oder strcpy sollten vermieden und durch sicherere Alternativen ersetzt werden:
    - **fgets**: Beschränkt die Eingabelänge und verhindert das Überschreiben des Puffers.
    - **strncpy**: Kopiert nur eine definierte Anzahl von Zeichen in den Zielpuffer.
    - **Verwendung von Standardbibliotheken**: In Sprachen wie C++ bieten Klassen wie std::string Mechanismen, die PuƯergrenzen automatisch verwalten.
- Überprüfung der Puffergrößen
  - Entwicklern wird empfohlen, die maximale Größe eines Puffers genau zu berechnen und einzuhalten.
  - Schleifen und Array-ZugriƯe sollten mit Grenzprüfungen versehen sein, um Off-by-One-Fehler oder andere Überläufe zu vermeiden.

**2. Testing**

Testing hilft dabei, Schwachstellen systematisch zu identifizieren und zu beheben, bevor
ein Programm eingesetzt wird.

**Statische Codeanalyse**
  - Statische Analysewerkzeuge wie Coverity oder SonarQube analysieren den Quellcode auf potenzielle Schwachstellen, wie unsichere Pufferzugriffe oder ungeschützte String-Verarbeitungen.
  - Diese Tools können automatisch problematische Stellen markieren, sodass Entwickler gezielt Maßnahmen ergreifen können.

**Fuzz-Testing**
  - Beim Fuzz-Testing werden Programme mit einer großen Anzahl zufälliger oder speziell manipulierter Eingaben getestet, um Schwachstellen wie Buffer Overflows aufzudecken.
  - Tools wie AFL (American Fuzzy Lop) oder libFuzzer generieren und testen Eingaben dynamisch, um Fehler in der Eingabeverarbeitung zu identifizieren.

**3. Extra Schutz**

Neben präventiven und testbasierten Maßnahmen gibt es Mechanismen auf Compiler- und Betriebssystemebene, die Buffer Overflow-Angriffe erschweren oder deren Auswirkungen begrenzen.

**Stackschutz (z. B. Canaries)**
  - Stack Canaries sind spezielle Werte, die zwischen lokalen Variablen und der Rücksprungadresse gespeichert werden. Vor der Rückkehr aus einer Funktion wird der Canary überprüft. Wenn er verändert wurde (z. B. durch einen BuƯer Overflow), erkennt das Programm den Angriff und kann ihn abwehren.

**Adressraum-Layout-Randomisierung (ASLR)**
  - ASLR verschiebt Speicherbereiche, wie den Stack, Heap und dynamische Bibliotheken, bei jedem Programmstart an unterschiedliche Adressen. Dadurch wird es Angreifern erheblich erschwert, die genauen Adressen für ihre AngriƯe zu ermitteln.

**Nicht-ausführbarer Stack und Heap**
  - Durch das Setzen des NX-Bits (No Execute) können bestimmte Speicherbereiche wie der Stack oder der Heap als nicht-ausführbar markiert werden. Dies verhindert, dass eingeschleuster Code, der dort platziert wurde, ausgeführt werden kann.

#### Integer Overflows 

Ein Integer Overflow tritt auf, wenn eine Zahl die darstellbare Größe eines Integer-Typs
übersteigt. Dies kann dazu führen, dass Berechnungen falsche Ergebnisse liefern oder
Speicherbereiche unvorhersehbar manipuliert werden. Da Integers in
Programmiersprachen eine feste Bit-Breite haben, können Werte, die die maximale
(oder minimale) darstellbare Größe überschreiten, fehlerhafte Zustände verursachen,
wie z. B. das "Zurücksetzen" auf 0 oder ein negatives Vorzeichen (Wraparound).

**Mitigation:**

**1. Prävention**
  - Validierung von Eingaben: <br>
  Externe Eingaben müssen auf gültige Wertebereiche überprüft werden, um Über- oder Unterläufe zu verhindern.
   Explizite Casts und keine Berechnungstricks: <br>
  Die Typkonvertierung sollte klar und absichtlich erfolgen, um unerwartete Veränderungen der Werte zu vermeiden. Vermeiden Sie Optimierungen, die Berechnungen schwer nachvollziehbar machen.
  - Verwendung sicherer Klassen: <br>
  Klassen wie SafeInt bieten in vielen Programmiersprachen Schutzmechanismen gegen Über- und Unterläufe.

**2. Testing**
  - Edge-Case-Tests: <br>
  Programme sollten mit extremen Eingaben getestet werden, z. B. Werten nahe der minimalen und maximalen Grenze des Integer-Typs.
  - Fuzz-Testing: <br>
  Automatisiertes Testen mit zufälligen und manipulativen Eingaben hilft, Schwachstellen in der Eingabeverarbeitung aufzudecken.

**3. Kompilerschutz**
  - Aktivierung spezieller Compiler-Flags wie -ftrapv, die signierte Integer-Überläufe erkennen und eine Fehlermeldung ausgeben, anstatt den falschen Wert weiter zu verarbeiten.

---

### Code Privileges and Stored Data Protection

#### Code Privileges
Erlauben Programmen und Skripten, mit bestimmten Berechtigungen zu operieren,
die kritisch für die Systemsicherheit sind.

**Unsachgemäße Berechtigungen**: Code läuft mit zu hohen Privilegien, was
Türöffner für Angreifer sein kann.

**Beispielproblem**: Übermäßiger Einsatz von sudo oder root.

**Gefahren**: Privilegieneskalation durch Ausnutzung von Schwachstellen.

**CVE-Beispiel**: CVE-2024-50590 "Elefant - Hasomed"

> Schwachstellen in fbserver.exe und fbguard.exe, die es lokalen Angreifern erlauben, diese zu überschreiben und als SYSTEM zu laufen, da sie mit zu hohen Rechten laufen.

**Mitigationsstrategien**:
  - Least Privilege Principle: Ausführung von Code mit minimal notwendigen Rechten.
  - Separation of Privilege: Funktionen mit höheren Privilegien isolieren und in getrennten Accounts mit begrenzten Rechten ausführen.

---

#### Stored Data Protection
Befasst sich mit dem Schutz gespeicherter Daten vor unbefugtem Zugriff und
Diebstahl.

**CWE**:
  - CWE-284: Gebrochene Zugriffskontrolle - Versagen von Authentifizierung, Autorisierung und Rechenschaftspflicht.
  - CWE-312 und CWE-318: Klartextspeicherung sensibler Informationen in zugänglichen oder ausführbaren Ressourcen.

**Beispiel eines Sicherheitsrisikos**: CVE-2021-34544 "Solar-Log 500"

> Passwörter werden im Klartext in Gerätedateien gespeichert, was unbefugten Zugriff erleichtert.

**Mitigationsstrategien**:
  - Verschlüsselung: Sensible Daten immer verschlüsselt speichern.
  - Zugriffskontrolle: Einschränken des Zugriffs auf sensible Dateien durch robuste Authentifizierungsmethoden.

---

### C++ Catastrophes

> 🚧 UNDER CONSTRUCTION 🚧

Fehler in C++ sind meistens eine von zwei Varianten.

1. Eine Klasse enthält einen _Function Pointer_. Wenn diese Klasse korrumpiert werden kann, kann der Programmfluß abgeändert werden

2. Eine Klasse mit einer oder mehreren virtuellen Methoden enthält einen _virtual function pointer table_ (vtable). Wenn die Klasse so abgeändert werden kann, dass der Pointer auf den vtable geändert werden kann, kontrolliert der Angreifer direkt den ausgeführten Code.

Ein Beispiel hier für wäre eine _double free_ Vulnerability, wird der gleiche Speicher zwei mal freigegeben, erlaubt dies einem Angreifer fast immer korrekt initialisierte Klassen im Speicher zu überschreiben.


**Mitigation**:

---

### Information Leakage Error and Exception Handling

#### Information Leakage

- Design-Problem
- Versehentliche Preisgabe interner Daten
- Unabsichtlich – Logisches Problem
- Absichtlich – Privacy Issues
- Fehler – Mangelndes Verständnis
- Hilfreiche Info vs. Verschleiern interner Daten

#### Exception Handling

- Implementations-Problem
- Versehentliche Preisgabe interner Daten
- Ausnahme + deren Behandlung wurden vernachlässigt
- Tiefe Einblicke in Systemstrukturen
- Ausführliche Fehlermeldungen direkt im Browser
- Keine exotischen Hacker-Tools nötig
- Informationen liegen schon unverschleiert bereit

**Mitigation**

- Code Reviews
- Sensitive Daten nicht ausgeben
- Fehlermeldungen abstrahieren
- \- return "Connection failed: " + serverIP;
- \+ return "Connection failed, please try again.“;
- Fehlermeldungen sammeln und analysieren
- Nur spezifische Exceptions fangen

---

### Race Conditions

Eine Race Condition ist ein Problem bei asynchronen bzw. parallelen Programmen, das dadurch auftritt, das mehrere Kontexte gleichzeitig versuchen auf eine geteilte Ressource zuzugreifen und sich dabei in die Quere kommen.
  - Ein Kontext kann dabei ein Prozess, ein Thread, aber auch beispielsweise eine menschliche Aktion (z.B.: File umbenennen/speichern, etc..) sein.
  - Eine Ressource kann dabei jede Art von technischer Information sein. Das wären also beispielsweise eine Datei, eine FIFO-Pipe, eine Datenbank, etc.

Dadurch können einige Probleme auftreten, unter anderen:
  - Die Integrität von Daten könnte verletzt werden. Dadurch, dass eine Ressource gleichzeitig gelesen und bearbeitet werden kann, kann es zu Inkonsistenzen kommen.
  - Unvorhergesehene Ereignisse können dazu führen, dass sich der Ausgang bzw. das Verhalten eines Programms bei jeder Ausführung ändert.

**Mitigation / Abhilfe**

Die folgenden Dinge helfen grundsätzlich dabei, Race Conditions in Programmen zu
vermeiden:
  - Minimieren des Codes, der auf Seiteneffekten, wie beispielsweise Dateien beruht.
  - Verwenden von sogenannten „reentrant-safe“ Funktionen für Signal-Handlers, die durch parallele Verwendung keine Race Conditions verursachen.
  - Keine globalen Variablen verwenden, ohne diese bei Verwendung mit Mutexes oder ähnlichem zu locken.
  - Sofern temporäre Dateien verwendet werden, sollten diese in Speicherbereiche geschrieben werden, wo nicht jeder User darauf Zugriff hat.

Im Code wird das umgesetzt durch:
  - **Synchronisations-Mechanismen**: Durch das Verwenden von Locks/Mutexes kann sichergestellt werden, dass nur ein Thread / Prozess auf kritischen Code zur selben Zeit zugreifen kann.
  - **Thread-sichere Datenstrukturen**: Viele Programmiersprachen bieten Thread- sichere Datenstrukturen an, wie beispielsweise Queues, Lists oder Maps.
  - **Immutable-Objekte**: Da immutable Objekte nach dem Erstellen nicht mehr verändert werden können, ist keine Synchronisation mehr notwendig.

---

## Threat Modeling

**Merksatz:**

Beim **Threat Modeling** schaut man sich speziell den Kreuzungspunkt von Datenfluss und Vertrauensgrenze (Trust Boundary) an.

