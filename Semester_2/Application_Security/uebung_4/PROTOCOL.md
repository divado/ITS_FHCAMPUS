# Übung 4 - Docker

## System einrichten

```bash
# Docker installieren
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# Benutzer zur Docker-Gruppe hinzufügen
sudo usermod -aG docker $USER

# Anmeldung neu laden, um Gruppenänderungen zu aktivieren
newgrp docker
```

## Informationen

```bash
# 1. Standardnetzwerke anzeigen
docker network ls
docker network inspect bridge
docker network inspect host
docker network inspect none

# 2. Storage Backend anzeigen
docker info | grep "Storage Driver"
docker info | grep -A 10 "Storage Driver"

# 3. Security-Optionen anzeigen
docker info | grep Security
```

## Container

```bash
# Image einer Linux-Distribution (z.B. Ubuntu) holen
docker pull ubuntu:latest

# Shell im Container starten
docker run -it --name test-container ubuntu:latest /bin/bash

# In einem anderen Terminal den Container-Status anzeigen während die Shell läuft
docker ps

# Nach dem Schließen der Shell
docker ps -a

# User des Prozesses auf dem Host anzeigen
ps aux | grep docker

# Gesammelte Einstellungen des Containers anzeigen
docker inspect test-container

# Container löschen
docker rm test-container
```

## Ausbruch

```bash
# Lesen einer Host-Datei über Docker (z.B. /etc/passwd)
docker run --rm -v /etc/passwd:/tmp/passwd:ro ubuntu:latest cat /tmp/passwd

# Schreiben einer Host-Datei über Docker (ACHTUNG: nur für Demonstrationszwecke)
docker run --rm -v /tmp:/mnt ubuntu:latest sh -c 'echo "Dies ist ein Test" > /mnt/test-file.txt'

# Zugriff auf das ganze Dateisystem
docker run -it --rm -v /:/host ubuntu:latest chroot /host
```

## Dockerfile

```bash
# Verzeichnis für das Projekt erstellen
mkdir -p ~/docker-webserver/html
cd ~/docker-webserver

# Einfache HTML-Datei erstellen
echo "<html><body><h1>Mein Webserver</h1></body></html>" > html/index.html

# Dockerfile erstellen
cat > Dockerfile <<EOF
FROM nginx:alpine
COPY html /usr/share/nginx/html
USER nginx
EXPOSE 80
EOF

# Image bauen
docker build -t my-webserver .

# Container starten mit interner Netzwerkverbindung
docker run -d --name webserver --network bridge my-webserver

# Reverse Proxy Container erstellen und starten
cat > proxy.conf <<EOF
server {
    listen 80;
    location / {
        proxy_pass http://webserver:80;
    }
}
EOF

docker run -d --name reverse-proxy \
    -p 127.0.0.1:8080:80 \
    -v $(pwd)/proxy.conf:/etc/nginx/conf.d/default.conf \
    --network bridge \
    nginx:alpine

# Logs anzeigen
docker logs webserver
```

## Netzwerk

```bash
# Eigene Netzwerke erstellen
docker network create webdb-network
docker network create isolated-network

# Webserver Container im webdb-Netzwerk starten
docker stop webserver
docker rm webserver
docker run -d --name webserver --network webdb-network my-webserver

# Datenbank-Container im selben Netzwerk starten
docker run -d --name database --network webdb-network postgres:alpine

# Isolierten Container in anderem Netzwerk starten
docker run -d --name isolated-container --network isolated-network alpine sleep infinity

# Überprüfen der Netzwerkkonfiguration
docker network inspect webdb-network
docker network inspect isolated-network

# Testen der Konnektivität (von Webserver zur DB)
docker exec webserver ping -c 2 database

# Testen der Isolation (sollte fehlschlagen)
docker exec isolated-container ping -c 2 webserver
```

## Capabilities

```bash
# nginx mit minimalen Capabilities starten
docker run -d --name secure-nginx \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --cap-add CHOWN \
    --cap-add SETGID \
    --cap-add SETUID \
    --cap-add DAC_OVERRIDE \
    -p 127.0.0.1:8081:80 \
    nginx:alpine

# Überprüfen der Capabilities
docker inspect --format '{{.HostConfig.CapAdd}}' secure-nginx
docker inspect --format '{{.HostConfig.CapDrop}}' secure-nginx
```

## Docker Security Bench

```bash
# Docker Security Bench herunterladen und ausführen
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh

# Warnung 2.14 beheben (Container von neuen Privilegien einschränken)
sudo mkdir -p /etc/docker
echo '{
  "no-new-privileges": true
}' | sudo tee /etc/docker/daemon.json

# Docker-Daemon neu starten
sudo systemctl restart docker

# Überprüfen Sie die Konfiguration
docker info | grep "No New Privileges"
```

## Aufräumen

```bash
# Alle gestoppten Container löschen
docker container prune -f

# Alle nicht verwendeten Images löschen
docker image prune -a -f

# Alle nicht verwendeten Netzwerke löschen
docker network prune -f

# Alle nicht verwendeten Volumes löschen
docker volume prune -f

# Alles auf einmal bereinigen
docker system prune -a -f
```
