FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache tzdata jq

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/
COPY run.sh /run.sh

# CRLF -> LF (falls du run.sh unter Windows editiert hast)
RUN sed -i 's/\r$//' /run.sh && chmod +x /run.sh

CMD ["/bin/sh", "/run.sh"]