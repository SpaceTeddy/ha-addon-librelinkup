FROM python:3.12-alpine

WORKDIR /app

# tzdata für lokale Zeit/Europe/Berlin, plus ca-certs für HTTPS
RUN apk add --no-cache tzdata ca-certificates

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# App
COPY app/ /app/
COPY run.sh /run.sh

# CRLF->LF fix + executable
RUN sed -i 's/\r$//' /run.sh && chmod +x /run.sh

CMD ["/run.sh"]