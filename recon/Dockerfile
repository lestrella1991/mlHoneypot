FROM python:3.12-alpine

ARG USER_ID=1000
ARG GROUP_ID=1000
ARG USER_NAME=recon

RUN apk add --no-cache bash ca-certificates curl git build-base go nginx

ENV CGO_ENABLED=0 \
    GOBIN=/usr/local/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/tomnomnom/httprobe@latest

RUN addgroup \
      -g "${GROUP_ID}" \
      "${USER_NAME}" \
    && adduser \
      -D \
      -u "${USER_ID}" \
      -G "${USER_NAME}" \
      -s /bin/bash \
      "${USER_NAME}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot_cloner_v3.py /app/honeypot_cloner.py
COPY generate_nginx.py /app/generate_nginx.py
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && mkdir -p \
       /work/sites \
       /work/generated/sites \
       /work/recon \
    && chown -R \
       "${USER_ID}:${GROUP_ID}" \
       /app \
       /work

USER ${USER_ID}:${GROUP_ID}

ENTRYPOINT ["/app/entrypoint.sh"]
