
FROM ubuntu
MAINTAINER isaac@behrenshome.com

RUN apt-get update
RUN apt-get dist-upgrade -y

# Install app requirements
RUN apt-get install -y python3 python3-pip

# Add application files
ADD app.py             /opt/vyos-fw-gui/app.py
ADD firewall_form.html /opt/vyos-fw-gui/firewall_form.html
ADD requirements.txt   /opt/vyos-fw-gui/requirements.txt
ADD templates/*        /opt/vyos-fw-gui/templates/

# Install pip modules
RUN pip3 install -r /opt/vyos-fw-gui/requirements.txt

# Set ownership of application files
RUN chown -R www-data:www-data /opt/vyos-fw-gui

USER www-data:www-data
WORKDIR /opt/vyos-fw-gui
ENTRYPOINT ["/usr/bin/env", "python3", "app.py"]

EXPOSE 8080/tcp
