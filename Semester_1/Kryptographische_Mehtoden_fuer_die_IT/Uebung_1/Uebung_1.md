# Übung 1

In einem Worst-Case müssten wir für alle nöglichen Kombinationen der Bits eines Key berechnen. Da wir davon ausgehen dürfen, dass bereits nach der Hälfte der möglichen Kombinationen der korrekte Key gefunden wurde, können wir die Anzahl der Kombinationen halbieren. Für Aufgabe a) bedeutet das Konkret $2^{63}$ anstatt $2^{64}$ mögliche Kombinationen.

Die Anzahl der möglichen Kombinationen wird durch die Anzahl der pro Sekunde möglichen Test-Kombinationen geteilt, in unserem Fall $4 GHz$ also $4*10^9Hz$.

Um die Exponenten-Regeln nutzen zu können wird der Exponent der zur Basis 2 auf die Basis 10 umgerechnet. 

Wir erhalten damit für Aufgabe a) das folgende Ergebnis:

$$
\frac{2^{63}}{4*10^9Hz}=\frac{9.2*10^{18}}{4*10^9Hz}=2.3*10^9s \approx 73 years
$$


Die Berechnung wurde Analog für die Aufgaben b) und c) durchgeführt. Wir erhalten damit für die Aufgabe b) das Ergebnis:

$$
\frac{2^{79}}{4*10^9Hz}=\frac{6*10^{23}}{4*10^9Hz}=1.5*10^14s \approx 4756468 years
$$

Für die Aufgabe c) erhalten wir das Ergebnis:

$$
\frac{2^{255}}{4*10^9Hz}=\frac{5.8*10^{76}}{4*10^9Hz}=1.45*10^67s \approx 4.6*10^{59} years
$$