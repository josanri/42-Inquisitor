FROM python:3.8.16-bullseye
WORKDIR /inquisitor

ARG IP-src
ARG MAC-src
ARG IP-target
ARG MAC-target

RUN apt-get update && apt-get install python3-dev libpcap-dev libnet-dev -y

RUN pip3 install --upgrade pip
RUN pip3 install scapy
RUN pip3 install argparse
RUN pip3 install pcapy

COPY inquisitor.py ./

CMD [ "python3" , "inquisitor.py", "$IP-src", "$MAC-src",  "$IP-target", "$MAC-target"]