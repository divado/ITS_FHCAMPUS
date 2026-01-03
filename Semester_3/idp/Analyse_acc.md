# Anaylse der Adaptiver Crusie Control (ACC)

- *graceful termination error*: When system is shut down gracefully, the ACC throws a SEGFAULT error. Fehlerursache in pigpio-Bibliothek. Eugener Signalhandler implemenetiret, weil BT Server Side constructior eine blocking Funktion aufruft und sich daher durch Strg+C nicht beenden lässt. Es kann während blocking auf eine Connection gewartet wird nicht auf Signale gepollt werden.
btconnectioncpp:23

- *btconnectioncpp:receiveWithCounterAndMac:299*: if message is big enough, counter is checked for validity against a local counter initialized with 0. Last received counter has to be bigger than the last received valid counter. In the beginning, the first message might be dropped because the local counter is 0 and the first received counter is also 0 which drops the first message.

- *MISRA Requirements*: Not all values returned by functions are checked for validity. For example, main.cpp:44-50

- *Widget update*: If ACC is turned on but BT connection is disconnected right after, ACC widget should show off because ACC got turned off due to lost connection. Currently, widget still shows ACC as on, even though ACC is off.