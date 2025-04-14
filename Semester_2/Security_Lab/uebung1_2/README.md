# Übungsblatt 1. Planung eines Netzwerk (Übung 1.1)


Gruppenmitglieder: (Gruppe 6)
- Philip Magnus
- Astrid Kuzma-Kuzniarski 

This documents shows the implementation of a network infrastructure with three network segments (LAN, DMZ, untrusted zone). A range of different clients and a vulnerable web server will be implemented, such as an internal Windows system and an external Kali Linux -"Attacker", and a Windows Server 2012 with DVWA.

General Information: 
During the lab, we switched to Proxmox to simplify the work and saving of data. 
During work, we also switched the Servers from the Windows 12 Server to an Ubuntu 24.04 Server, due to the configuration of vulnerable Webserver. 

## Network Plan

IP Ranges:

| Network | IP-(Range)            | What       | Interface |
|:--------|:----------------------|:-----------|:----------|
| Green   | 192.168.10.121/24     | Internet   | eno1      |
| Yellow  | 10.120.[0-127].0/17   | DMZ        | enp3s0f0  |
| Red     | 10.120.[128-255].0/17 | LAN        | enp3s0f1  |
| Blue    | 10.0.0.0/24           | Management |           |

Green (Internet):

    192.168.10.121 - router
    192.168.10.195 - Kali/Parrot Client

Yellow (DMZ):

    10.120.0.1 - router
    10.120.0.3 - Windows 2012 Server
    

Red (LAN):

    10.120.128.1 - router
    10.110.128.3 - Windows 7 Client

Blue (management):

    10.0.0.2 - vSRX Firewall # WiP

![](screenshots/JvbJQTC.png)

## Installation 

For our Virtual Maschines we use VirtualBox. We copy the VMs locally and create clones of them. The VMs are installed on two hosts and connected through the physical network. The IP addresses have beed manually assigned to the VMs.

The following clients have beed installed: 

- Kali
- Windows 7_SP1
- Windows Server_2012
- Ubuntu Server 24.04

After the cloning of a machine, we go to the "Settings" -> "Network" and set the adapters as "Bridged Adapter" and connect with the correct interfaces:

###### YELLOW: 
![](screenshots/screen2.png)


###### RED:
![](screenshots/screen3.png)



Now we use the following command do activate the physical interfaces: 

```console
$ for x in enp3s0f0 enp3s0f1 ; do suodp ip l set $x up ; done
```

![](screenshots/screen4.png)

To configure the networks in the router, we modify the `/etc/netplan/00-installer-config.yaml`:

```yaml
network:
    version: 2
    ethernets:
        ens20: # green
            dhcp4: false
            addresses: 
                - 192.168.10.121/24
            routes:
                - to: 0.0.0.0/0
                  via: 192.168.11.1
            nameservers:
                addresses: [8.8.8.8, 8.8.4.4]                
        ens21: # red
            addresses: 
                - 10.120.120.1/17 
        ens22: #yellow
            addresses:
                - 10.120.0.1/17 
```    

Now we activate the frouting from red to yellow: 

```
sudo su -
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -A FORWARD -i ens21 -o ens22 -j ACCEPT
iptables -A FORWARD -o ens21 -i ens22 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

Setting up nat on router:
NAT : 

```bash
iptables -t nat -P OUTPUT ACCEPT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -A POSTROUTING -o ens22 -j MASQUERADE
```

To save our `iptables` configuration the `iptables-persistent` package was installed.

```bash
apt install iptables-persistent -y
```

To save the made changes we ran the following command:

```bash
iptables-save > /etc/iptables/rules.v4
```

For making the ipv4 forwarding rule permanent we created a file under ` /etc/sysctl.d/10-forward.conf` with the following single line as its content.

```bash
net.ipv4.ip_forward = 1
```

For our `DNS` and `DHCP` configuration we installed `dnsamasq`. 

```bash
sudo apt install dnsmasq -y
```



Now we configure the DNS forwarding:

```console
$ sudo apt install bind9
```
in the `/etc/bind/named.conf.options` the following config needs to be changed:

![](screenshots/screen5.png)


### Windows 7 settings: 

We started our client machine on a Windows 7 VM and set the configuration of the Internet to satic, as follows: 

![](screenshots/screen6.png)

Now we test, if we have a connection, by usind the `ping`command to our router:


![](screenshots/screen7.png)


### Windows 12:

On our Windowas 12 Server we make the following configurations: 

Start > Systemsteuerung > Netzwerk- und Freigabecenter

- disable the Firewall (which in general in not recomended)

![](screenshots/screen8.png)


![](screenshots/screen9.png)

Then we tried to download and install the XAMPP for the DVWA. 
ATTENTION: Issues with the installed Browser, we needed to install Mozilla Firefox first to continue with the task. 

## Proxmox

The main reasons that we switched to Proxmox: 
- hardware performance 
- persistent: 
    - We don´t have to copay the VMs on the computer on which we are working in the lab. 
    - Internet connection works better and we have an improvement in speed
    - Constant access --> We can work from anywhere at anytime 

Main changes: 

- Switching from Windows 12 Server to Ubuntu 24.04
- Vulnerable Web App (DVWA) on Docker

#### New network plan: 

![](screenshots/screen10.png)



### Installation

The installation didn´t change much, but we needed to adapt a few things. 

- Reinstall Windows 7 

## Setup DVWA

### Installation Docker

```bash
sudo apt update
sudo apt install apt-transport-https curl
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
```
```bash
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

## Vulnerability Scanner - Nessus

We install a new Kali VM and download Nessus from: https://www.tenable.com/downloads/nessus
The correct version needs to be selected to work on the operating system. Therefore, for Kali we install: `Linux - Debian - amd64`


After the download process, we install the `.deb` package:

```shell=
sudo dpkg -i ~/Downloads/Nessus-10.8.3-ubuntu1604_amd64.deb 
[sudo] Passwort für kali: 
Vormals nicht ausgewähltes Paket nessus wird gewählt.
(Lese Datenbank ... 407856 Dateien und Verzeichnisse sind derzeit installiert.)
Vorbereitung zum Entpacken von .../Nessus-10.8.3-ubuntu1604_amd64.deb ...
Entpacken von nessus (10.8.3) ...
nessus (10.8.3) wird eingerichtet ...
HMAC : (Module_Integrity) : Pass
SHA1 : (KAT_Digest) : Pass
SHA2 : (KAT_Digest) : Pass
SHA3 : (KAT_Digest) : Pass
TDES : (KAT_Cipher) : Pass
AES_GCM : (KAT_Cipher) : Pass
AES_ECB_Decrypt : (KAT_Cipher) : Pass
RSA : (KAT_Signature) : RNG : (Continuous_RNG_Test) : Pass
Pass
ECDSA : (PCT_Signature) : Pass
ECDSA : (PCT_Signature) : Pass
DSA : (PCT_Signature) : Pass
TLS13_KDF_EXTRACT : (KAT_KDF) : Pass
TLS13_KDF_EXPAND : (KAT_KDF) : Pass
TLS12_PRF : (KAT_KDF) : Pass
PBKDF2 : (KAT_KDF) : Pass
SSHKDF : (KAT_KDF) : Pass
KBKDF : (KAT_KDF) : Pass
HKDF : (KAT_KDF) : Pass
SSKDF : (KAT_KDF) : Pass
X963KDF : (KAT_KDF) : Pass                                                                                                                   
X942KDF : (KAT_KDF) : Pass                                                                                                                   
HASH : (DRBG) : Pass                                                                                                                         
CTR : (DRBG) : Pass                                                                                                                          
HMAC : (DRBG) : Pass                                                                                                                         
DH : (KAT_KA) : Pass                                                                                                                         
ECDH : (KAT_KA) : Pass                                                                                                                       
RSA_Encrypt : (KAT_AsymmetricCipher) : Pass                                                                                                  
RSA_Decrypt : (KAT_AsymmetricCipher) : Pass                                                                                                  
RSA_Decrypt : (KAT_AsymmetricCipher) : Pass                                                                                                  
INSTALL PASSED                                                                                                                               
Unpacking Nessus Scanner Core Components...                                                                                                  
 
 - You can start Nessus Scanner by typing /bin/systemctl start nessusd.service                                                               
 - Then go to https://kali:8834/ to configure your scanner   
```

Then we start Nessus daemon:
```bash
$ sudo systemctl start nessusd.service
```

![](screenshots/screen11.jpeg)


### Setup Nessus

The setup wizard pops up and we need to follow the following steps: 

- We choose the selection option "Register for Nessus Essentials", which offers the free version of Nessus for educators, students, and hobbyists.

![](screenshots/screen12.jpeg)


Here we receive the valid licence and the activation code:

![](screenshots/screen13.jpeg)


Then we need to create an account: 
For the Username we choose: fh-campus-team6
Passwort: fhcampus6


Then we are waiting for the initialization. After that step we should be able to start our first scannings. 
![](screenshots/screen14.jpeg)



![](screenshots/screen15.jpeg)




## Firewall

<!-- For the Firewall we will use Pfsense -->

For our firewall we are using a Juniper Networks vSRX Firewall with the following virutal hardware.

![](screenshots/screen16.png)

The firewall was installed using the cqow2 Image provided by Juniper Networks.

For an initial configuration we executed the following basic configuration steps.

First we entered `cli mode` in the JunOS system on our vSRX VM.

```bash
root#cli
root@>
```

From the `cli` we activated the configuration mode to start editing our comfiguration.

```bash
configure
[edit]
root@#
```

Next we set a new password for our root user, for this we chose the password `Firewall`. 

```bash
[edit]
root@# set system root-authentication plain-text-password
New password: ********
Retype new password: ********
```

After setting a new password we also set a new host-name for our firewall for which we chose `vSRX`.

```bash
[edit]
root@# set system host-name vSRX
```

Next we set up the `fxp0`managemnt interface to be active and use a dhcp-client to obtain an out-of-band management IP address. This address will later be used to acces the J-Web GUI for easier configuration of the firewall.

```bash
[edit]
root@# set interfaces fxp0 unit 0 family inet dhcp-client
```

After the management interface we setup an initial generic interface and added it to a security trust zone. This interface can later be changed via the web GUI.

```bash
[edit]
root@# set interfaces ge-0/0/0 unit 0 family inet dhcp-client
```

```bash
[edit]
root@# set security zones security-zone trust interfaces ge-0/0/0.0
```

Lastly we checked our changes before a commit for any errors. After the checks completed successfully we commited the changes to the configuration.

```bash
[edit]
root@# commit check
configuration check succeeds
```

```bash
[edit]
root@#commitcommit
complete
```

With the `show` command we can view the config after the initial configuration steps.

```bash
root@vSRX# show 
## Last changed: 2025-04-13 19:07:36 UTC
version 23.2R2.21;
system {
    host-name vSRX;
    root-authentication {
        encrypted-password "$6$TsmRNjet$g6erK1vNp5XNZsIACUfAlemcyYuGaaMxOda0jfaIVppW49eLw0SxU1Z.ltWCHWNxofbvU/F4IpARVHEOqy4Uv."; ## SECRET-DATA
    }
    services {
        ssh;
        web-management {
            http {
                interface fxp0.0;
            }
            https {
                system-generated-certificate;
                interface fxp0.0;
            }
        }
    }
    syslog {
        file interactive-commands {
            interactive-commands any;
        }                               
        file messages {                 
            any any;                    
            authorization info;         
        }                               
    }                                   
    license {                           
        autoupdate {                    
            url https://ae1.juniper.net/junos/key_retrieval;
        }                               
        keys {                          
            key "E419777401 aeaqic apaeor 4altdy arwhqb impacr i6bmed embrgu ydgmbz bqihmu 2slawu u5lonf ygk4sf ozqwyb ziukrz o4t4tq 73ypay 2pgysd icl7im u5x4l3 4pgvmf cggson fslbu7 atr27n sh6zqe s2rq";
        }                               
    }                                   
}                                       
security {                              
    pki {                               
        ca-profile ISRG_Root_X1 {       
            ca-identity ISRG_Root_X1;   
            pre-load;                   
        }                               
        ca-profile Lets_Encrypt {       
            ca-identity Lets_Encrypt;   
            enrollment {                
                url https://acme-v02.api.letsencrypt.org/directory;
            }                           
        }                               
    }                                   
    screen {                            
        ids-option untrust-screen {     
            icmp {                      
                ping-death;             
            }                           
            ip {                        
                source-route-option;    
                tear-drop;              
            }                           
            tcp {                       
                syn-flood {             
                    alarm-threshold 1024;
                    attack-threshold 200;
                    source-threshold 1024;
                    destination-threshold 2048;
                    queue-size 2000; ## Warning: 'queue-size' is deprecated
                    timeout 20;         
                }                       
                land;                   
            }                           
        }                               
    }                                   
    policies {                          
        from-zone trust to-zone trust { 
            policy default-permit {     
                match {                 
                    source-address any; 
                    destination-address any;
                    application any;    
                }                       
                then {                  
                    permit;             
                }                       
            }                           
        }                               
        from-zone trust to-zone untrust {
            policy default-permit {     
                match {                 
                    source-address any; 
                    destination-address any;
                    application any;    
                }                       
                then {                  
                    permit;             
                }                       
            }                           
        }                               
        pre-id-default-policy {         
            then {                      
                log {                   
                    session-close;      
                }                       
            }                           
        }                               
    }                                   
    zones {                             
        security-zone trust {           
            tcp-rst;                    
            interfaces {                
                ge-0/0/0.0;             
            }                           
        }                               
        security-zone untrust {         
            screen untrust-screen;      
        }                               
    }                                   
}                                       
interfaces {                            
    ge-0/0/0 {                          
        unit 0 {                        
            family inet {               
                dhcp;                   
            }                           
        }                               
    }                                   
    fxp0 {                              
        unit 0 {                        
            family inet {               
                dhcp;                   
            }                           
        }                               
    }                                   
}
```

All further configuration will take place via the J-Web GUI which can be reached by calling the webserver running on the management interface of the vSRX-Firewall. The interface can be reached over its out-of-band IP address. This would be equivalent to setting up a hardware firewall through its management port.

> NOTE: The management IP can be set to an in-band address. This is highly discouraged by the manufacturer through their best practices. This is done mainly to reduce security risks and attack surfaces.

We can login to the management GUI with the known user password combination of `root:Firewall`. 

![J-Web Interface](screenshots/screen17.png)

After a succesful login we are presented with the basic settings screen.

![Basic settings](screenshots/screen18.png)

## SIEM 

For the SIEM we will use ELK Stack, Apache Metron

## EDR

OSSEC


