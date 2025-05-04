Here’s a step-by-step guide to configure your Juniper vSRX to act as both a firewall and router for your scenario:

---

## **Step 1: Assign Interfaces**

Choose three interfaces for WAN, DMZ, and LAN. Example mapping:

| Interface    | Zone | IP Address         | Subnet Mask     |
|--------------|------|--------------------|-----------------|
| ge-0/0/1.0   | WAN  | 192.168.11.1       | 255.255.255.0   |
| ge-0/0/2.0   | DMZ  | 10.120.0.1         | 255.255.128.0   |
| ge-0/0/3.0   | LAN  | 10.120.128.1       | 255.255.128.0   |

---

## **Step 2: Configure Interfaces**

```sh
configure

set interfaces ge-0/0/1 unit 0 family inet address 192.168.11.1/24
set interfaces ge-0/0/2 unit 0 family inet address 10.120.0.1/17
set interfaces ge-0/0/3 unit 0 family inet address 10.120.128.1/17
```

---

## **Step 3: Create Security Zones**

```sh
set security zones security-zone WAN interfaces ge-0/0/1.0
set security zones security-zone DMZ interfaces ge-0/0/2.0
set security zones security-zone LAN interfaces ge-0/0/3.0
```

---

## **Step 4: Set Up Security Policies**

1. **Allow LAN to WAN (internet access for workstations):**
    ```sh
    set security policies from-zone LAN to-zone WAN policy allow-lan-to-wan match source-address any destination-address any application any
    set security policies from-zone LAN to-zone WAN policy allow-lan-to-wan then permit
    ```

2. **Allow WAN to DMZ (webserver access from WAN):**
    ```sh
    set security policies from-zone WAN to-zone DMZ policy allow-wan-to-dmz-web match source-address any destination-address any application any
    set security policies from-zone WAN to-zone DMZ policy allow-wan-to-dmz-web then permit
    ```

3. **Allow LAN to DMZ (webserver access from LAN):**
    ```sh
    set security policies from-zone LAN to-zone DMZ policy allow-lan-to-dmz-web match source-address any destination-address any application any
    set security policies from-zone LAN to-zone DMZ policy allow-lan-to-dmz-web then permit
    ```

4. **Allow DMZ to WAN (optional, e.g., webserver updates):**
    ```sh
    set security policies from-zone DMZ to-zone WAN policy allow-dmz-to-wan match source-address any destination-address any application any
    set security policies from-zone DMZ to-zone WAN policy allow-dmz-to-wan then permit
    ```

5. **Block all other traffic by default:**
    ```sh
    set security policies default-policy deny-all
    ```

---

## **Step 5: Enable Routing (Default in Junos)**

- Junos enables routing between interfaces by default when they have IP addresses.
- If you need static routes or a default route, add as needed.  
  Example: If WAN is your upstream, set a default route:
    ```sh
    set routing-options static route 0.0.0.0/0 next-hop <WAN-Gateway-IP>
    ```

---

## **Step 6: (Optional) Configure DHCP Server**

If you want vSRX to provide DHCP to LAN/DMZ:

- **LAN:**
    ```sh
    set system services dhcp-local-server group LAN_DHCP interface ge-0/0/3.0
    set access address-assignment pool LAN_POOL family inet network 10.120.128.0/17
    set access address-assignment pool LAN_POOL family inet range LAN_RANGE low 10.120.128.10
    set access address-assignment pool LAN_POOL family inet range LAN_RANGE high 10.120.128.200
    set access address-assignment pool LAN_POOL family inet dhcp-attributes router 10.120.128.1
    set system services dhcp-local-server group LAN_DHCP overrides access-profile LAN_POOL
    ```

- **DMZ:** (if needed)
    ```sh
    set system services dhcp-local-server group DMZ_DHCP interface ge-0/0/2.0
    set access address-assignment pool DMZ_POOL family inet network 10.120.0.0/17
    set access address-assignment pool DMZ_POOL family inet range DMZ_RANGE low 10.120.0.10
    set access address-assignment pool DMZ_POOL family inet range DMZ_RANGE high 10.120.0.200
    set access address-assignment pool DMZ_POOL family inet dhcp-attributes router 10.120.0.1
    set system services dhcp-local-server group DMZ_DHCP overrides access-profile DMZ_POOL
    ```

---

## **Step 7: Commit Configuration**

```sh
commit and-quit
```

---

## **Network Flow Summary**

- Workstations in LAN get IP from vSRX (if DHCP enabled), use 10.120.128.1 as gateway, can access WAN and DMZ webserver.
- Webserver in DMZ has IP 10.120.0.x, accessible from both WAN and LAN.
- Security policies strictly control access between zones.

---

**If you want a sample configuration file, or have questions about NAT, or want to see the J-Web GUI steps for this setup, just ask!**