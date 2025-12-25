FROM ubuntu:22.04

RUN apt-get update -q \
    && apt-get install -q -y --no-install-recommends \
        build-essential \
        libssl-dev \
        socat \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m signing

WORKDIR /home/signing

COPY src/ .

RUN gcc -o chall chall.c rsa.c prime.c base85.c -lcrypto

RUN chown -R root:signing /home/signing \
    && chmod -R 750 /home/signing \
    && chmod 740 flag

USER signing

CMD socat -T 60 -d -d TCP-LISTEN:1340,reuseaddr,fork EXEC:'./chall'
