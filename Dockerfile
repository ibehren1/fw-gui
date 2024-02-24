FROM ubuntu:22.04
MAINTAINER isaac@behrenshome.com

RUN apt-get update
RUN apt-get dist-upgrade -y

# Install app requirements
RUN apt-get install -y python3 python3-pip
RUN pip3 install --upgrade pip

# Add application files
ADD .version           /opt/fw-gui/.version
ADD app.py             /opt/fw-gui/app.py
ADD package/*          /opt/fw-gui/package/
ADD examples/*         /opt/fw-gui/examples/
ADD static/*           /opt/fw-gui/static/
ADD templates/*        /opt/fw-gui/templates/
ADD requirements.txt   /opt/fw-gui/requirements.txt
RUN mkdir              /opt/fw-gui/data

# Install pip modules
RUN pip3 install -r /opt/fw-gui/requirements.txt

# Set ownership of application files
RUN chown -R www-data:www-data /opt/fw-gui

USER www-data:www-data
WORKDIR /opt/fw-gui
ENTRYPOINT ["/usr/bin/env", "python3", "app.py"]

EXPOSE 8080/tcp
