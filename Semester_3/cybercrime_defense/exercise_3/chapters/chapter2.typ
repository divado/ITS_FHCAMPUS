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