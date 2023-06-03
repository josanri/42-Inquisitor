FROM python:3.8.16-bullseye
WORKDIR /inquisitor

ENV IP_SRC=$IP_SRC
ENV MAC_SRC=$MAC_SRC
ENV IP_TARGET=$IP_TARGET
ENV MAC_TARGET=$MAC_TARGET

RUN apt-get update && apt-get install python3-dev libpcap-dev libnet-dev -y

RUN pip3 install --upgrade pip
RUN pip3 install scapy
RUN pip3 install argparse
RUN pip3 install pcapy

COPY inquisitor.py ./

CMD python3 inquisitor.py $IP_SRC $MAC_SRC $IP_TARGET $MAC_TARGET