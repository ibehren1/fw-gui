FROM ubuntu:22.04
MAINTAINER isaac@behrenshome.com

RUN apt-get update
RUN apt-get dist-upgrade -y

# Install app requirements
RUN apt-get install -y python3 python3-pip
RUN pip3 install --upgrade pip

# Add application files
ADD app.py             /opt/vyos-fw-gui/app.py
ADD package/*          /opt/vyos-fw-gui/package/
ADD examples/*         /opt/vyos-fw-gui/examples/
ADD templates/*        /opt/vyos-fw-gui/templates/
ADD requirements.txt   /opt/vyos-fw-gui/requirements.txt
RUN mkdir              /opt/vyos-fw-gui/data

# Install pip modules
RUN pip3 install -r /opt/vyos-fw-gui/requirements.txt

# Set ownership of application files
RUN chown -R www-data:www-data /opt/vyos-fw-gui

USER www-data:www-data
WORKDIR /opt/vyos-fw-gui
ENTRYPOINT ["/usr/bin/env", "python3", "app.py"]

EXPOSE 8080/tcp
