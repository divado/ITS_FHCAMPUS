= Assignment

== Setup
#v(0.5cm)

First we create a new directory for our assignment and navigate into it:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ mkdir ccd_assignment3
    $ cd ccd_assignment3
    ```,
    caption: "Creating and navigating into assignment directory."
  )
])

#v(0.5cm)

Before we started the setup of our `nginx` we downloaded the `testsslk.sh` test suite.\
The download was done via `git clone` from the official GitHub repository:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ git clone https://github.com/drwetter/testssl.sh
    $ cd testssl.sh
    $ chmod +x testssl.sh
    ```,
    caption: "Cloning the testssl.sh repository."
  )
])

#v(0.5cm)

Before starting and setting up our `nginx` server, we need to check that `Docker` is installed and set up correctly.\

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker --version
    Docker version 29.1.1, build 0aedba5
    ```,
    caption: "Checking Docker installation."
  )
])

#v(0.5cm)

After confirming `Docker`is installed we checked if the `Docker` daemon is running.\

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ sudo systemctl status docker
    [sudo] password for philip:
    ● docker.service - Docker Application Container Engine
        Loaded: loaded (/usr/lib/systemd/system/docker.service; enabled; preset: enabled)
        Active: active (running) since Sun 2025-11-30 19:00:48 CET; 24h ago
    TriggeredBy: ● docker.socket
          Docs: https://docs.docker.com
      Main PID: 10839 (dockerd)
          Tasks: 24
        Memory: 30.1M (peak: 40.7M)
            CPU: 4.590s
        CGroup: /system.slice/docker.service
                └─10839 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock

     [Ommited for better readability]           
    ```,
    caption: "Checking if Docker service is running."
  )
])
#v(0.5cm)

We also added our user to the `docker` group to be able to run `docker` commands without `sudo`:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ sudo usermod -aG docker $USER
    ```,
    caption: "Adding user to docker group."
  )
])

#v(0.5cm)

Next we pulled the `nginx` image from the Docker Hub repository to our local machine:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker pull nginx
    ```,
    caption: "Pulling the nginx image from Docker Hub."
  )
])

#v(0.5cm)

After pulling the image we checked if the image is available locally:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker images
    ```,
    caption: "Pulling the nginx image from Docker Hub."
  )
])

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/docker_pull_images.png"),
    caption: "Listing local Docker images."
  )
])

#v(0.5cm)

For a baseline test we started a simple `nginx` container without any custom configuration and ran the `testssl.sh` test suite against it:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker run -d -p 80:80 -p443:443 --name nginx_test nginx
    ```,
    caption: "Running a simple nginx container for baseline testing."
  )
])

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ ./testssl.sh --full localhost:443
    ```,
    caption: "Running testssl.sh against the nginx container."
  )
])

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/testssl_1.png"),
    caption: "Testssl.sh results for the baseline nginx container."
  )
])

#v(0.5cm)

As we can see from the results above `testssl.sh` says that no valid `TLS/SSL` service is enabled on the server.

#pagebreak()

== Configuring HTTPS with Self-Signed Certificates

First we took a look at the default `nginx` configuration file located at `/etc/nginx/conf.d/default.conf` inside the container:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker exec -it nginx_test /bin/bash

    $ root@a2662f959694:/# cat /etc/nginx/conf.d/default.conf

      server {
          listen       80;
          listen  [::]:80;
          server_name  localhost;

          #access_log  /var/log/nginx/host.access.log  main;

          location / {
              root   /usr/share/nginx/html;
              index  index.html index.htm;
          }

          #error_page  404              /404.html;

          # redirect server error pages to the static page /50x.html
          #
          error_page   500 502 503 504  /50x.html;
          location = /50x.html {
              root   /usr/share/nginx/html;
          }

          # proxy the PHP scripts to Apache listening on 127.0.0.1:80
          #
          #location ~ \.php$ {
          #    proxy_pass   http://127.0.0.1;
          #}

          # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
          #
          #location ~ \.php$ {
          #    root           html;
          #    fastcgi_pass   127.0.0.1:9000;
          #    fastcgi_index  index.php;
          #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
          #    include        fastcgi_params;
          #}

          # deny access to .htaccess files, if Apache's document root
          # concurs with nginx's one
          #
          #location ~ /\.ht {
          #    deny  all;
          #}
      }
    ```,
    caption: "Viewing the default nginx configuration file."
  )
])

#v(0.5cm)

In the configuation file we can see that the `nginx` server is set to listen on port `80` for `HTTP` traffic. There is also no configuration for `TLS/SSL` in form of a `TLS` block or certificates, which makes any `HTTPS` connection impossible.

Since we need to enable `HTTPS` on our server we created a self-signed certificate using `OpenSSL` with the following command:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $  openssl req -new -newkey rsa:4096 -nodes -keyout nginx.key -x509 -days 365 -out nginx_test.crt

    .........+.......+..+.......+.....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+....+..+...............+...+.+..+.......+.....+...+..................+..........+.........+..+....+..+.......+........+.............+...........+..........+...............+...+...+..............+..................+.....................+.+..............+.+....................+.+........+....+......+.........+.....+..................+..........+...+......+........+.+...............+..+...+...............+.......+...............+..+.......+...+........+...+..........+..+.......+...+..+......+.......+..............+.+...............+...+..+.......+..+...+...+...............+....+...+......+......+.....+.+..+.............+...+............+..+......+......+.+........+....+..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    ......+......+..+...+.+...+...+..+..........+.....+.............+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+...+......+..+...+............+....+.....+...+.+......+..............+.+......+..+...+.......+..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+....+...............+............+.....+...+.......+.........+..+..........+..................+.........+...+........+......+....+...........+...............+...+..........+...+..+.+..............+......+......+...+......+..............................+..........+...........+....+..+..........+.....+...+.........+..................+....+.....+...+...+.........+.+.....+...+......+....+..+......................+...+............+...+..+.......+.....+....+.....+.+..............+..........+.........+..+...+................+.....+.+........+.+.........+......+...........+......+.................................+.........+.......+...+..+..........+...+...+........+.........+.+.....+.......+....................+....+..................+.....+..........+..+....+......+......+.................+.............+...+......+...+...+..+...+.......+..+....+..+...+....+..+.+...+........................+......+............+...+......+...........+.......+.....+............+.+.....+...+...........................+............+......+.+.....+..........+...........+...+.........+..............................+.......+...+...............+......+.....+.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    -----
    You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.
    -----
    Country Name (2 letter code) [AU]:AU
    State or Province Name (full name) [Some-State]:Vienna
    Locality Name (eg, city) []:Vienna
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:HCW
    Organizational Unit Name (eg, section) []:CCD
    Common Name (e.g. server FQDN or YOUR name) []:localhost
    Email Address []:test@hcw.ac.at
    ```,
    caption: "Generating a self-signed certificate using OpenSSL."
  )
])

#v(0.5cm)

This command generates a new RSA private key (`nginx.key`) and a self-signed certificate (`nginx_test.crt`) valid for `365` days. The information in the certificate such as `Country Name`, `State`, `Organization`, and `Common Name` were filled out as prompted.

For organizational purposes we created a new directory called `tls` to store our generated certificate and key:


#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ mkdir tls
    $ mv nginx.key nginx.crt tls/
    ```,
    caption: "Move key and cert to tls directory."
  )
])

#v(0.5cm)

To make the certificate and key available to the `nginx` container we need to copy the files into the `docker` container. We can do this using the `docker cp` command:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker cp nginx_test.crt nginx_test:/etc/nginx/nginx_test.crt
      Successfully copied 4.1kB to nginx_test:/etc/nginx/nginx_test.crt
    $ docker cp nginx.key nginx_test:/etc/nginx/nginx.key
      Successfully copied 5.12kB to nginx_test:/etc/nginx/nginx.key
    ```,
    caption: "Copying key and cert to nginx container."
  )
])

#v(0.5cm)

Next we need to modify the `nginx` configuration to enable `HTTPS` on port $443$ using our self-signed certificate. For this we edit the default configuration file located at `/etc/nginx/conf.d/default.conf` inside the container (for ease of use we create a new `default.conf` file outside the container and copy it in later):

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vim default.conf

      server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate      /etc/nginx/tls/nginx_test.crt;
        ssl_certificate_key  /etc/nginx/tls/nginx.key;

        ssl_protocols TLSv1.2 TLSv1.3;

        ssl_session_tickets off;

        ssl_ciphers HIGH:!aNULL:!MD5:!SHA1:!RSA:!3DES;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
      }
    ```,
    caption: "Editing the nginx configuration file."
  )
])

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker cp default.conf nginx_test:/etc/nginx/conf.d/default.conf
      
      Successfully copied 2.05kB to nginx_test:/etc/nginx/conf.d/default.conf
    ```,
    caption: "Copying modified configuration into nginx container."
  )
])

#v(0.5cm)

We finally moved the certificate and key into a new `tls` directory inside the container for better organization:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ root@a2662f959694:/# cd /etc/nginx/
    $ root@a2662f959694:/etc/nginx# mkdir tls
    $ root@a2662f959694:/etc/nginx# mv nginx_test.crt nginx.key tls/
    ```,
    caption: "Copying key and certificate to tls directory."
  )
])

#v(0.5cm)

Next we restarted the `nginx` server to apply the new configuration:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ root@a2662f959694:/etc/nginx/tls# nginx -s reload
      
      2025/12/15 22:32:05 [notice] 87#87: signal process started
    ```,
    caption: "Reloading nginx to apply new configuration."
  )
])

#v(0.5cm)

We can now run the `testssl.sh` test suite again against our `nginx` server to see if `HTTPS` is now enabled:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ /testssl.sh --full --add-ca tls/nginx.crt localhost:443
    ```,
    caption: "Running testssl.sh against nginx server with HTTPS enabled."
  )
])

#v(0.5cm)

We can see that `SSL/TLS` is now enabled on our server. We used the `--add-ca` option to add our self-signed certificate as a trusted certificate authority for the test (full output in appendix 1).

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/testssl_2.png"),
    caption: "Testssl.sh results for nginx server with HTTPS enabled."
  )
])

== Fine Tuning and Hardening

However, this is not the final configuration we want to use. We want to further harden our `TLS` configuration by disabling weak ciphers and protocols.

Since the previous configuration was only used as a simple test, we decided to create a completely new configuration file based on the current Mozilla Security Guidelines (Modern TLS). In order to cleanly replace the existing settings, the previous file was revised and reloaded into the container as before. The previous minimal configuration has now been replaced by a comprehensively hardened server block:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ vim default.conf

      server {
        listen 80;
        server_name localhost;
        # HTTP → HTTPS Weiterleitung
        return 301 https://$host$request_uri;
      }

      server {
          listen 443 ssl;
          server_name localhost;

          ssl_certificate      /etc/nginx/tls/nginx_test.crt;
          ssl_certificate_key  /etc/nginx/tls/nginx.key;

          ssl_protocols TLSv1.2 TLSv1.3;

          ssl_session_tickets off;

          ssl_ciphers 'TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES256-GCM-SHA384';

          # TLS 1.3 Cipher suites overwrite (necessary for full points)
          ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

          ssl_ecdh_curve secp384r1;

          ssl_prefer_server_ciphers on;

          ssl_session_cache shared:SSL:1m;
          ssl_session_timeout 1m;

          add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

          location / {
              root /usr/share/nginx/html;
              index index.html;
          }
        }
    ```,
    caption: "Running testssl.sh against nginx server with HTTPS enabled."
  )
])

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker cp tls/default.conf nginx_test:/etc/nginx/conf.d/default.conf
      
      Successfully copied 2.56kB to nginx_test:/etc/nginx/conf.d/default.conf
    ```,
    caption: "Copying hardened configuration into nginx container."
  )
])

#v(0.5cm)

Finally we reloaded the `nginx` server to apply the new hardened configuration:

#v(0.5cm)

#align(center, block[
  #figure(
    ```bash
    $ docker exec -it nginx_test nginx -s reload
    
    2025/12/15 22:51:35 [notice] 104#104: signal process started
    ```,
    caption: "Reloading hardened configuration."
  )
])

#v(0.5cm)

We can now run the `testssl.sh` test suite again against our hardened `nginx` server to see the results with the maximum score possible:

#v(0.5cm)

#align(center, block[
  #figure(
    image("../figures/testssl_3.png"),
    caption: "Testssl.sh results for nginx with max score."
  )
])

#v(0.5cm)

The full output of the final testssl.sh run can be found in appendix 2.

Finally the key, certificate, and configuration were packed into a `zip` including this writeup for submission.

#pagebreak()