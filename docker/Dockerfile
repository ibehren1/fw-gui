FROM ubuntu:24.04
MAINTAINER isaac@behrenshome.com

# Update OS packages
RUN apt-get update && \ 
    apt-get dist-upgrade -y

# Install app requirements
RUN apt-get install -y python3 python3-pip zip
    #pip3 install --break-system-packages --upgrade pip

# Clean-up apt cache
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add application files
ADD examples/.env.prod     /opt/fw-gui/.env
ADD .version               /opt/fw-gui/.version
ADD app.py                 /opt/fw-gui/app.py
ADD examples/example.json  /opt/fw-gui/examples/
ADD package/*              /opt/fw-gui/package/
ADD requirements.txt       /opt/fw-gui/requirements.txt
ADD static/*               /opt/fw-gui/static/
ADD templates/*            /opt/fw-gui/templates/
RUN mkdir                  /opt/fw-gui/data
RUN mkdir                  /opt/fw-gui/data/mongo_dumps

# Install pip modules
RUN pip3 install --break-system-packages -r /opt/fw-gui/requirements.txt

# Set ownership of application and data files
RUN chown -R www-data:www-data /opt/fw-gui

USER www-data:www-data
WORKDIR /opt/fw-gui
ENTRYPOINT ["/usr/bin/env", "python3", "app.py"]

EXPOSE 8080/tcp
