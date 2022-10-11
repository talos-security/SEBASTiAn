FROM python:3.8.6-slim-buster

# Copy requirements and install.
COPY ./requirements.txt /SEBASTiAn/
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir -r /SEBASTiAn/requirements.txt

# Copy the needed files.
COPY ./SEBASTiAn/ /SEBASTiAn/SEBASTiAn/
COPY ./cli.py /SEBASTiAn/

# Set the working directory (to be used when mounting files from the host).
WORKDIR /workdir
VOLUME /workidr

# Set the entrypoint to SEBASTiAn command line interface.
ENV PYTHONPATH="/SEBASTiAn"

ENTRYPOINT ["python3", "-m", "cli"]
