# VyOS-FW-GUI

## GUI for Managing VyOS Firewall Rule Configurations

The web GUI allows the user to visually create and manage group objects, firewall chains/rules and filter chains/rules for multiple firewalls. Additionally, user can push the created policy to the firewalls via SSH connectivity via the Napalm-VyOS framework or download the configuation commands to apply via console. Additionally, user can import/export a JSON file of the vyos-fw-gui configuration to move between instances of the GUI.

| | |
| - | - |
| Source Code | [https://github.com/ibehren1/vyos-fw-gui](https://github.com/ibehren1/vyos-fw-gui)  |
| Docker Hub | [https://hub.docker.com/repository/docker/ibehren1/vyos-fw-gui/general](https://hub.docker.com/repository/docker/ibehren1/vyos-fw-gui/general)  |
| Working Demo | [https://vyos-fw-gui.com](https://vyos-fw-gui.com)|

### Recommended Usage

Deploy via Docker on a server/VM that will be used to manage multiple VyOS Firewall instances.  Use [Nginx Proxy Manager](https://nginxproxymanager.com/) (also via Docker) on the same host to provide LetsEncrypt TLS encrytion between client (web browser) and VyOS-FW-GUI.

You can also host the VyOS-FW-GUI as a container on the VyOS device you wish to manage.  Setting up TLS in this case can be provided using [ACME on VyOS](https://docs.vyos.io/en/sagitta/configuration/pki/index.html#acme).

While recommended deployment is via Docker, also inculded in the repo is a systemd service file for use with local install.  

See [Deployment](#deployment) section below for configuration commands.

### Known Issue

When deployed behind HAProxy (VyOS load-balancing reverse-proxy) timeouts can prevent diffs and commits for firewalls with large configurations.  Issue is not obeserved connecting directly to app when hosted in Docker or behind Nginx proxy.

Resolution: TBD

## Commiting to the Firewall

Connections to the firewall are made using the [Napalm-VyOS library](https://github.com/napalm-automation-community/napalm-vyos) via SSH.  Napalm for VyOS only allows merging configurations (changes with existing) and does not allow for replacing configuriations (new replacing existing).  As such, by default, if you remove an item from the config and push, it will not be removed from the firewall as the configs are merged.  To work around this, the View Diffs and Commit interface has the option to preface the firewall configuration with a 'delete firewall' command.  This causes the configuration to remove all firewall configuration and then add the specified configuration settings so that the net configuration is a replacement of the existing configuration.  You will __NOT__ want to use this feature unless you are managing __ALL__ firewall configuations via the GUI.

![images](./images/commit.png)

## Initial Login

There is no initial username and password.  After starting the application, use the "Register as a new user" link to create your username and password.  Once you have registered your user(s), you can disable user registration by updating the environment variable in Docker configuration to `DISABLE_REGISTRATION=True`. Doing this will remove the link to the registration page and stop any POSTS to the route /user_registration from being processed.  This can be reenabled anytime you need to setup users.

Future releases *may* include administration and user management features.

## Deployment

### Container on VyOS

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

### Docker Run

```bash
docker volume create vyos-fw-gui_data

docker run \
  --name   vyos-fw-gui \
  --expose 8080 \
  --env DISABLE_REGISTRATION=False \
  --mount  source=vyos-fw-gui_data,target=/opt/vyos-fw-gui/data \
  ibehren1/vyos-fw-gui:v0.12.1
```

### Docker Compose

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
