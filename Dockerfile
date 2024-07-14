# FROM ubuntu:22.04
FROM mongo:latest
MAINTAINER isaac@behrenshome.com

# Update OS packages
RUN apt-get update && \ 
    apt-get dist-upgrade -y

# Install app requirements
RUN apt-get install -y python3 python3-pip zip supervisor && \
    pip3 install --upgrade pip

# Clean-up apt cache
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add application files
ADD .env               /opt/fw-gui/.env
ADD .version           /opt/fw-gui/.version
ADD app.py             /opt/fw-gui/app.py
ADD examples/*         /opt/fw-gui/examples/
ADD package/*          /opt/fw-gui/package/
ADD requirements.txt   /opt/fw-gui/requirements.txt
ADD static/*           /opt/fw-gui/static/
ADD templates/*        /opt/fw-gui/templates/
ADD supervisord.conf   /etc/supervisor/conf.d/supervisord.conf 
RUN mkdir              /opt/fw-gui/data
RUN mkdir              /opt/fw-gui/data/mongodb

# Install pip modules
RUN pip3 install -r /opt/fw-gui/requirements.txt

# Set ownership of application and data files
RUN chown -R www-data:www-data /opt/fw-gui
RUN chown -R mongodb:mongodb /opt/fw-gui/data/mongodb

ENTRYPOINT ["/usr/bin/supervisord"]

EXPOSE 8080/tcp
