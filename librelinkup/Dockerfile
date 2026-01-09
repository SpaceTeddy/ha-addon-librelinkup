ARG BUILD_FROM
FROM $BUILD_FROM

WORKDIR /app

# Python + pip
RUN apk add --no-cache python3 py3-pip && python3 -m pip install --no-cache-dir --upgrade pip

# App
COPY app/ /app/
RUN python3 -m pip install --no-cache-dir -r /app/requirements.txt

# S6 overlay run script
COPY rootfs/ /

RUN chmod +x /run.sh

CMD [ "/run.sh" ]