# vyos-fw-gui

## GUI for creating VyOS firewall rule configuration commands

The webform generates and displays the syntactically correct configuration commands can then be cp/pasted to the CLI for firewall rule configuration.

Source code: [https://github.com/ibehren1/vyos-fw-gui]( https://github.com/ibehren1/vyos-fw-gui)  
Working demo:  [https://vyosfwgui.com](https://vyosfwgui.com)

## Interface

![image](./images/vyos-fw-gui_interface_1.png)
![image](./images/vyos-fw-gui_interface_2.png)
![image](./images/vyos-fw-gui_interface_3.png)
![image](./images/vyos-fw-gui_interface_4.png)

## Sample Output

```text
#
# ipv4
#

#
# Table: WAN_IN
#
set firewall ipv4 name WAN_IN default-action 'drop'
set firewall ipv4 name WAN_IN description 'WAN Inbound to LAN'


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
```

## Docker Run

```bash
docker volume create vyos-fw-gui_data

docker run \
  --name vyos-fw-gui \
  -p 8080:8080 \
  --mount source=vyos-fw-gui_data,target=/opt/vyos-fw-gui/data \
  ibehren1/vyos-fw-gui:arm64|amd64
```

## Docker Compose

```yaml
version: '3.7'
services:
  vyos-fw-gui:
    image: ibehren1/vyos-fw-gui:arm64|amd64
    container_name: vyos-fw-gui
    ports:
      - 8080:8080/tcp
    restart: unless-stopped
    volumes:
      - data:/opt/vyos-fw-gui/data
volumes:
  data:
```
