FROM python:3.12-slim

RUN apt update && apt install -y socat
RUN /usr/sbin/useradd --no-create-home -u 1000 user
WORKDIR /home/user
COPY . .
RUN chmod +x unredacted_chall.py
RUN pip install pycryptodome

USER user

CMD socat \
	TCP-LISTEN:1337,reuseaddr,fork \
	EXEC:"python ./unredacted_chall.py"
