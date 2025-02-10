# Prüfungsvorbereitung

## Aufgabe 1 

a) Erklären Sie die Programmiersünde _Format String Problems_ (Bug). Bei welcher Art von Befehlen tritt diese auf?

Ein Format String Bug wird durch die falsche Verwendung von Format String Funktionen verrursacht. Wenn im Code Format String Funktionen verwendet werden um nicht vertrauenswürdige Benutzereingaben zu formatieren, kann es bei falscher Nutzung dieser Funktion einem Nutzer möglich, durch die Verwendung von Format String Specifiern, beliebige Daten aus dem Programmspeicher auszulesen und evtl. sogar in diesen zu schreiben.

b) Geben Sie ein Beispiel in Codeform für ein _Format String_ Bug an.

Ein Beispiel wäre in C/C++:

```C 
printf(userInput);
```

UserInoput ist hier eine beliebige und ungeprüfte Eingabe durch einen Benutzer.


c) Welche Konsequenzen kann ein _Format String_ Bug haben? Nennen Sie mögliche Gegenmaßnahmen.

Ein Format String Bug kann weitreichende Konsequenzen haben. Ein Nutzer könnte beliebige Daten aus dem Programmspeicher auslesen und diesen evtl. sogar schreiben. Hierdurch können andere Fehler provoziert werden, z.B. Buffer Overflows, oder Injection Schwachstellen, wie z.B. SQL Injections, ausgentzt werden.

Mögliche Gegenmaßnahmen:

- Validieren der Benutzereingaben, z.B. durch Whitelisting
- Korrekte Verwendung von Format String Funktionen mit den entsprechenden Specifiern, z.B.:
  - `printf("%s", userInput);`


## Aufgabe 2 

Betrachten Sie den folgenden Source Code:

```C 
#include <stdio.h>  
#include <string.h>  

int main(int argc, char* argv[]) {  
  char input[50];  
  int(input_lgth) = strlen(argv[1]);  
  int copy_lgth;  

  if (input_lgth > 50) {  
      copy_lgth = 50;  
    } else {  
      copy_lgth = input_lgth + 1;  
    }
    
    strncpy(char input, argv[1], copy_lgth);  

    printf("%s", input);  
    return 0;  
}  
```
a) Welche Sünde verbirgt sich in diesem Beispiel? Wo befindet sich diese? Gibt es Programmiersprachen, die nicht betroffen sind? Wenn ja, welche?

Die Sünde ist ein Buffer Overflow, wenn die Eingabe genau eine Länge von 50 hat. Die copy_lgth wird dann auf 51 gesetzt und überschreibt den Speicher mit einem Zeichen zu viel. Bei einer Länge von genau 50 würde strncpy() auch den Puffer voll schreiben, und keinen Null-Terminator hinzufügen, was zu unerwartetem Verhalten führen kann. Programmiersprachen mit automatischer Speicherverwaltung und sicheren String-Funktionen wären von Buffer Overflows eher nicht betroffen, aber auch hier lässt es sich nicht ganz ausschließen. (z.B. Java, Python)

b) Welche Konsequenzen verursacht diese Sünde? Geben Sie 2 konkrete Auswirkungen an.

Ein Buffer Overflow überschreibt den benachbarten Speichern und die darin enthaltenen Daten. Dies kann entweder zu einem Absturz des Programms führen oder in Extremfällen einem Angreifer ermöglichen arbiträre Daten in den Speicher zu schreiben und so den Programmfluss zu ändern.

c) Wie kann diese verhindert werden? Korrigieren Sie den betreffenden Code Abschnitt.

```C
#include <stdio.h>  
#include <string.h>  

int main(int argc, char* argv[]) {  
  int input_lgth = strlen(argv[1])
  char input[copy_lgth];  
    
  strncpy(char input, argv[1], input_lgth);

  printf("%s", input);  
  return 0;  
}  
```

## Aufgabe 3 

a) Erklären Sie im Kontext von Git die Begriffe **Branches** und **Merge**.

1. **Branches** Ein Branch ist eine historische Abfolge von Commits in einem Git Repository. Z.B. der Main Branch, develop Branch und die hiervon abzweigenden feature Branches.

Aus der offiziellen Git Doku -> "Ein beweglicher Pointer auf einen Commit."

2. **Merge** ein Merge bezeichnet eine Zusammenführung von zwei Branches. Wenn zwei Branches nach einer voneinander unabhängigen Entwicklung wieder zusammengeführt werden spricht man von einem Merge.

b) Im folgenden sehen Sie einen Ausschnitt aus einer mit git-flow erstellten git History. Ordnen Sie den Farben den zugehörigen Branch Typ zu.

![git-flow](./screenshots/02%20Feature%20branches.svg)

- Der Vollständigkeit halber eine gute Ressource zum lernen von git-flow: [Atlassian](https://www.atlassian.com/de/git/tutorials/comparing-workflows/gitflow-workflow)

c) Wie wird die Integrity in einem Git-Repository gewährleistet?

Jeder Commit, sowie jedes File wird in Git mit einer Checksum durch SHA1 gekennzeichnet und gespeichert. Eine Änderung an einem Commit hätte so auch eine Änderung des Commit-Hashes zur folge.

## Aufgabe 4 

Die folgenden Fragen zielen auf das Security-Modell in Webbrowsern ab.

a) Nehmen wir an, in einem Webbrowser sind zwei Tabs offen. In einem steht in der Adressleiste `https://www.example.com:443/dir1/index.html`, und in der Adressleiste des anderen Tabs steht `https://www.example.com/dir2/other.html`. Werden die beiden Seiten als derselbe _Origin_ betrachtet?

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
  
## Aufgabe 5 

a) Was ist der Unterschied zwischen Authentifizierung und Autorisierung?

b) Was können Sie bei er Entwickliung einer Webapplikation gegen das Problem "unsichere direkte Objektreferenzen" tun? Es gibt genau eine richtige Antwort.

- Die zugehörigkeit des aufgerufenen Objecktes zum/zur aktuell angemeldeten Benutzer*In überprüfen.
  - [ ] Wahr 
  - [ ] Falsch
- Bei jeder Anfrage überprüfen, ob das aktuelle Konto die entsprechende Rolle hat, um die Funktion aufzurufen.
  - [ ] Wahr 
  - [ ] Falsch 
- TLS für die Transportverschlüsselung einsetzen.
  - [ ] Wahr 
  - [ ] Falsch 
- Aufsteigende Objekt-IDs verwenden.
  - [ ] Wahr
  - [ ] Falsch 

## Aufgabe 6

Welcher ist der Unterschied zwischen den Maßnahmen gegen Reflected Cross-Site Scripting und Stored Cross-Site Scripting?

- Bei Stored XSS passiert die Ausgabekodierung in der Datenbank, bei Reflected XSS bei der Ausgabe
  - [ ] Wahr
  - [ ] Falsch
- Bei Stored XSS ist die Ausgbaenkodierung unabhängig vom jeweiligen Ausgabekontext.
  - [ ] Wahr
  - [ ] Falsch
- Es gibt keinen grundsätzlichen Unterschied
  - [ ] Wahr
  - [ ] Falsch
- Whitelisting von Eingabeparametern ist bei Stored XSS wirkungslos
  - [ ] Wahr
  - [ ] Falsch

## Aufgabe 7

a) Wie funktionieren, generisch gesprochen, Injection-Angriffe, und zwar unabhängig von der Technologie (SQL, SMTPO, LDAP, etc.)?

b) Nehmen wir an, es gebe eine OS-Command-Injection-Lücke in einer Webapplikation, die erfolgreich ausgenützt wird. Im Kontext welches Betriebssytembenutzers werden die injizierten Kommandos allgemein gesprochen ausgeführt?

- Mit dem root-Benutzer
  - [ ] Wahr
  - [ ] Falsch
- Als privelegierter Betriebssystembenutzer
  - [ ] Wahr
  - [ ] Falsch
- Als jender Benutzer, unter dem der Webserver bzw. Applikationsserver läuft.
  - [ ] Wahr
  - [ ] Falsch
- Als nichtprevilegierter Benutzer
  - [ ] Wahr
  - [ ] Falsch