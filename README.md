# vyos-fw-gui

## GUI for creating VyOS firewall rule configuration commands

The webform generates and displays the syntactically correct configuration commands can then be cp/pasted to the CLI for firewall rule configuration.

Source code: [https://github.com/ibehren1/vyos-fw-gui]( https://github.com/ibehren1/vyos-fw-gui)  
Working demo:  [https://vyosfwgui.behrenshome.com](https://vyosfwgui.behrenshome.com)

## Interface

![image](./images/vyos-fw-gui_interface.png)

## Sample Output

```text
#
# ipv4
#

#
# Table: table-name
#

# Rule 10
set firewall ipv4 name table-name rule 10 description 'Allow DNS.'
set firewall ipv4 name table-name rule 10 action accept
set firewall ipv4 name table-name rule 10 destination address 10.1.1.10
set firewall ipv4 name table-name rule 10 destination port 53
set firewall ipv4 name table-name rule 10 protocol tcp_udp
set firewall ipv4 name table-name rule 10 log
set firewall ipv4 name table-name rule 10 state 'new'
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
