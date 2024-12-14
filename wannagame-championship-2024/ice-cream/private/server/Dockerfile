FROM ubuntu:latest

RUN apt update -y && apt install socat python-is-python3 python3-pip -y
RUN pip install pycryptodome --break-system-packages
WORKDIR /
COPY chall.py / 
COPY flag.txt / 

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:\"python3 chall.py\",stderr"]
