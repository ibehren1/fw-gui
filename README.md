# vyos-fw-gui

## GUI for creating VyOS firewall rule configuration commands

The webform generates and displays the syntactically correct configuration commands can then be cp/pasted to the CLI for firewall rule configuration.

Source code: [https://github.com/ibehren1/vyos-fw-gui]( https://github.com/ibehren1/vyos-fw-gui)  
Working demo:  [https://vyos-fw-gui.com](https://vyos-fw-gui.com)

## Interface

![image](./images/vyos-fw-gui_interface_1.png)
![image](./images/vyos-fw-gui_interface_2.png)
![image](./images/vyos-fw-gui_interface_3.png)

## Sample Output

```text
#
# ipv4
#

#
# Groups
#
set firewall group address-group DNS_Servers description 'DNS_Servers'
set firewall group address-group DNS_Servers address '10.1.1.10'
set firewall group address-group DNS_Servers address '10.1.1.12'
set firewall group port-group DNS_Port description 'DNS_Port'
set firewall group port-group DNS_Port port '53'
set firewall group port-group SSH_Port description 'SSH_Port'
set firewall group port-group SSH_Port port '22'

#
# Table: WAN_LOCAL
#
set firewall ipv4 name WAN_LOCAL default-action 'drop'
set firewall ipv4 name WAN_LOCAL description 'WAN inbound to localhost.'


# Rule 10
set firewall ipv4 name WAN_LOCAL rule 10 description 'Allow established/related.'
set firewall ipv4 name WAN_LOCAL rule 10 action 'accept'
set firewall ipv4 name WAN_LOCAL rule 10 state 'established'
set firewall ipv4 name WAN_LOCAL rule 10 state 'related'

# Rule 20
set firewall ipv4 name WAN_LOCAL rule 20 description 'Drop invalid.'
set firewall ipv4 name WAN_LOCAL rule 20 action 'drop'
set firewall ipv4 name WAN_LOCAL rule 20 log
set firewall ipv4 name WAN_LOCAL rule 20 state 'invalid'

#
# Table: WAN_IN
#
set firewall ipv4 name WAN_IN default-action 'drop'
set firewall ipv4 name WAN_IN description 'WAN inbound to LAN.'


# Rule 10
set firewall ipv4 name WAN_IN rule 10 description 'Allow established/related.'
set firewall ipv4 name WAN_IN rule 10 action 'accept'
set firewall ipv4 name WAN_IN rule 10 state 'established'
set firewall ipv4 name WAN_IN rule 10 state 'related'

# Rule 20
set firewall ipv4 name WAN_IN rule 20 description 'Drop invalid.'
set firewall ipv4 name WAN_IN rule 20 action 'drop'
set firewall ipv4 name WAN_IN rule 20 log
set firewall ipv4 name WAN_IN rule 20 state 'invalid'

#
# ipv6
#

#
# Groups
#
set firewall group ipv6-address-group DNS_Servers description 'DNS_Servers'
set firewall group ipv6-address-group DNS_Servers address 'fc00::53'
set firewall group ipv6-port-group DNS_Port description 'DNS_Port'
set firewall group ipv6-port-group DNS_Port port '53'
set firewall group ipv6-port-group SSH_Port description 'SSH_Port'
set firewall group ipv6-port-group SSH_Port port '22'

#
# Table: WAN_LOCAL
#
set firewall ipv6 name WAN_LOCAL default-action 'drop'
set firewall ipv6 name WAN_LOCAL description 'WAN inbound to localhost.'


# Rule 10
set firewall ipv6 name WAN_LOCAL rule 10 description 'Allow established/related.'
set firewall ipv6 name WAN_LOCAL rule 10 action 'accept'
set firewall ipv6 name WAN_LOCAL rule 10 state 'established'
set firewall ipv6 name WAN_LOCAL rule 10 state 'related'

# Rule 20
set firewall ipv6 name WAN_LOCAL rule 20 description 'Drop invalid.'
set firewall ipv6 name WAN_LOCAL rule 20 action 'drop'
set firewall ipv6 name WAN_LOCAL rule 20 log
set firewall ipv6 name WAN_LOCAL rule 20 state 'invalid'

# Rule 30
set firewall ipv6 name WAN_LOCAL rule 30 description 'Allow ICMP.'
set firewall ipv6 name WAN_LOCAL rule 30 action 'accept'
set firewall ipv6 name WAN_LOCAL rule 30 protocol 'ipv6-icmp'

#
# Table: WAN_IN
#
set firewall ipv6 name WAN_IN default-action 'drop'
set firewall ipv6 name WAN_IN description 'WAN inbound to LAN.'


# Rule 10
set firewall ipv6 name WAN_IN rule 10 description 'Allow established/related.'
set firewall ipv6 name WAN_IN rule 10 action 'accept'
set firewall ipv6 name WAN_IN rule 10 state 'established'
set firewall ipv6 name WAN_IN rule 10 state 'related'

# Rule 20
set firewall ipv6 name WAN_IN rule 20 description 'Drop invalid.'
set firewall ipv6 name WAN_IN rule 20 action 'drop'
set firewall ipv6 name WAN_IN rule 20 log
set firewall ipv6 name WAN_IN rule 20 state 'invalid'

# Rule 30
set firewall ipv6 name WAN_IN rule 30 description 'Allow ICMP.'
set firewall ipv6 name WAN_IN rule 30 action 'accept'
set firewall ipv6 name WAN_IN rule 30 protocol 'ipv6-icmp'
```

## Docker Run

```bash
docker volume create vyos-fw-gui_data

docker run \
  --name   vyos-fw-gui \
  --expose 8080 \
  --mount  source=vyos-fw-gui_data,target=/opt/vyos-fw-gui/data \
  ibehren1/vyos-fw-gui:v0.3.0
```

## Docker Compose

```yaml
version: '3.7'
services:
  vyos-fw-gui:
    image: ibehren1/vyos-fw-gui:v0.3.0
    container_name: vyos-fw-gui
    ports:
      - 8080:8080/tcp
    restart: unless-stopped
    volumes:
      - data:/opt/vyos-fw-gui/data
volumes:
  data:
```
