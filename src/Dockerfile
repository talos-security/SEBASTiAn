FROM python:3.8.6-slim-buster

# Copy requirements and install.
COPY ./requirements.txt /motan/
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir -r /motan/requirements.txt

# Copy the needed files.
COPY ./motan/ /motan/motan/
COPY ./cli.py /motan/

# Set the working directory (to be used when mounting files from the host).
WORKDIR /workdir
VOLUME /workidr

# Set the entrypoint to motan command line interface.
ENV PYTHONPATH="/motan"

ENTRYPOINT ["python3", "-m", "cli"]
