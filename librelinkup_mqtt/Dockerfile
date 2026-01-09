FROM python:3.12-alpine

WORKDIR /data

RUN apk add --no-cache tzdata jq

COPY requirements.txt /data/requirements.txt
RUN pip install --no-cache-dir -r /data/requirements.txt

COPY main.py /main.py
COPY run.sh /run.sh
RUN sed -i 's/\r$//' /run.sh && chmod +x /run.sh

CMD ["/bin/sh", "/run.sh"]