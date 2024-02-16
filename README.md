# vyos-fw-gui

## GUI for creating VyOS firewall rule configurations

The web GUI allows the user to visually create and manage group objects, firewall chains/rules and filter chains/rules for multiple firewalls. Additionally, user can push the created policy to the firewalls via SSH connectivity via the Napalm framework or download the configuation commands to apply via console. Additionally, user can import/export a JSON file of the vyos-fw-gui configuration to move between instances of the GUI.

| | |
| - | - |
| Source code | [https://github.com/ibehren1/vyos-fw-gui](https://github.com/ibehren1/vyos-fw-gui)  |
| Docker Hub | [https://hub.docker.com/repository/docker/ibehren1/vyos-fw-gui/general](https://hub.docker.com/repository/docker/ibehren1/vyos-fw-gui/general)  |
| Working demo | [https://vyos-fw-gui.com](https://vyos-fw-gui.com)|

Recommended deployment is via Docker but also inculded in the repo is a systemd service file for use with local install.

### Known Issue

When deployed behind HAProxy (VyOS load-balancing reverse-proxy) timeouts can prevent diffs and commits for firewalls with large configurations.  Issue is not obeserved connecting directly to app when hosted in Docker or behind Nginx proxy.

## Container on VyOS

Run these commands to create the volume for the container and pull the image.

```bash
mkdir -p /config/vyos-fw-gui/data
sudo chown -R www-data:www-data /config/vyos-fw-gui
add container image ibehren1/vyos-fw-gui:v0.12.1
```

Run these commands to add the container to the VyOS configuration.

```bash
set container name vyos-fw-gui allow-host-networks
set container name vyos-fw-gui cap-add 'net-bind-service'
set container name vyos-fw-gui description 'VyOS FW GUI'
set container name vyos-fw-gui image 'ibehren1/vyos-fw-gui:v0.12.1'
set container name vyos-fw-gui environment DISABLE_REGISTRATION value 'False'
set container name vyos-fw-gui port http destination '8080'
set container name vyos-fw-gui port http protocol 'tcp'
set container name vyos-fw-gui port http source '80'
set container name vyos-fw-gui restart 'always'
set container name vyos-fw-gui volume vyosfwgui_data destination '/opt/vyos-fw-gui/data'
set container name vyos-fw-gui volume vyosfwgui_data source '/config/vyos-fw-gui/data'
```

## Docker Run

```bash
docker volume create vyos-fw-gui_data

docker run \
  --name   vyos-fw-gui \
  --expose 8080 \
  --env DISABLE_REGISTRATION=False \
  --mount  source=vyos-fw-gui_data,target=/opt/vyos-fw-gui/data \
  ibehren1/vyos-fw-gui:v0.12.1
```

## Docker Compose

```yaml
version: '3.7'
services:
  vyos-fw-gui:
    image: ibehren1/vyos-fw-gui:v0.12.1
    container_name: vyos-fw-gui
    environment:
      - DISABLE_REGISTRATION=False
    ports:
      - 8080:8080/tcp
    restart: unless-stopped
    volumes:
      - data:/opt/vyos-fw-gui/data
volumes:
  data:
```

## Interface

![image](./images/vyos-fw-gui_interface_1.png)
![image](./images/vyos-fw-gui_interface_2.png)
![image](./images/vyos-fw-gui_interface_3.png)
![image](./images/vyos-fw-gui_interface_4.png)
![image](./images/vyos-fw-gui_interface_5.png)
