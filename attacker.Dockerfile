FROM python:3.8-alpine3.17

WORKDIR /inquisitor

RUN apk update && apk add tcpdump libpcap-dev
RUN pip3 install scapy
RUN pip3 install libpcap

COPY inquisitor.py ./

CMD [ "python3" , "inquisitor.py" ]