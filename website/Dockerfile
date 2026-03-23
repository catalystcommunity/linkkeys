FROM python:slim as builder

WORKDIR /build
RUN pip install pysocha typing_extensions
COPY . .

RUN python -m pysocha build -c config.yaml

FROM caddy:2.9.1-alpine

WORKDIR /site
RUN mkdir /site/logs

COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=builder ./build/generated ./root
