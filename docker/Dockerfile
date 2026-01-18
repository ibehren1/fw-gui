FROM ubuntu:24.04
LABEL org.opencontainers.image.authors="isaac@behrenshome.com"

# Update OS packages
RUN apt-get update && \
    apt-get dist-upgrade -y

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Clean-up apt cache
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add application files
ADD examples/.env.prod     /opt/fw-gui/.env
ADD .version               /opt/fw-gui/.version
ADD app.py                 /opt/fw-gui/app.py
ADD examples/example.json  /opt/fw-gui/examples/
ADD package/*              /opt/fw-gui/package/
ADD pyproject.toml         /opt/fw-gui/pyproject.toml
ADD uv.lock                /opt/fw-gui/uv.lock
ADD static/*               /opt/fw-gui/static/
ADD templates/*            /opt/fw-gui/templates/
RUN mkdir                  /opt/fw-gui/data
RUN mkdir                  /opt/fw-gui/data/mongo_dumps

# Set ownership of application and data files
RUN chown -R www-data:www-data /opt/fw-gui

# Set user and working directory
USER www-data:www-data
WORKDIR /opt/fw-gui

# Set environment variables
ENV UV_CACHE_DIR=/tmp/uv-cache
ENV UV_TOOL_DIR=/tmp/uv-tools
ENV UV_PYTHON_INSTALL_DIR=/tmp/uv-python

# Install pip modules
RUN uv sync

USER www-data:www-data
WORKDIR /opt/fw-gui
ENTRYPOINT ["uv", "run", "--no-project", "app.py"]


EXPOSE 8080/tcp
