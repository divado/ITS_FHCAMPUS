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
  char_input[50];  
  int(input_lgth) strlen(argv[1]);  
  int copy_lgth;  

  if (input_lgth > 50) {  
      copy_lgth = 50;  
    } else {  
      copy_lgth = input_lgth + 1;  
    }
    
    strncpy(input, argv[1], copy_lgth);  

    printf("%%s", input);  
    return 0;  
}  
```
a) Welche Sünde verbirgt sich in diesem Beispiel? Wo befindet sich diese? Gibt es Programmiersprachen, die nicht betroffen sind? Wenn ja, welche?

b) Welche Konsequenzen verursacht diese Sünde? Geben Sie 2 konkrete Auswirkungen an.

c) Wie kann diese verhindert werden? Korrigieren Sie den betreffenden Code Abschnitt.

## Aufgabe 3 

a) Erklären Sie im Kontext von Git die Begriffe **Branches** und **Merge**.

b) Im folgenden sehen Sie einen Ausschnitt aus einer mit git-flow erstellten git History. Ordnen Sie den Farben den zugehörigen Branch Typ zu.

![git-flow](./screenshots/02%20Feature%20branches.svg)

c) Wie wird die Integrity in einem Git-Repository gewährleistet?

## Aufgabe 4 

Die folgenden Fragen zielen auf das Security-Modell in Webbrowsern ab.

a) Nehmen wir an, in einem Webbrowser sind zwei Tabs offen. In einem steht in der Adressleiste `https://www.example.com:443/dir1/index.html`, und in der Adressleiste des anderen Tabs steht `https://www.example.com/dir2/other.html`. Werden die beiden Seiten als derselbe _Origin_ betrachtet?

b) Beschreiben Sie den Unterschied zwischen implizierter und expliziter Authentifizierung bei Webapplikationen.

c) Was bewirkt die Same-Origin Policy?

- Dass beim Aufruf von Ressourcen fremder Seiten die HTTP-Antwort nicht z.B. per JavaScript wörtlich gelesen werden darf.
  - [ ] Wahr 
  - [ ] Falsch 
- Das innerhalb einer Seite (Origin) clientseitig keinerlei HTTP-Requests zu fremden Seiten gesendet werden können.
  - [ ] Wahr 
  - [ ] Falsch 
- Das Webseiten keinerlei Ressourcen (JavaScript, CSS, etc.) von fremden Domänen einbinden dürfen.
  - [ ] Wahr 
  - [ ] Falsch 
- Das _Cross-Site Request Forgery_-Angriffe vollständig verhindert werden.
  - [ ] Wahr 
  - [ ] Falsch
  
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
