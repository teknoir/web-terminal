FROM python:3.6-alpine3.14
COPY ./ /app
WORKDIR /app

RUN apk add --no-cache bash tini openssh-client libwebsockets\
    && pip3 install -r requirements.txt
 
RUN apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing \
      corkscrew && \
      rm -rf /var/cache/apk/*

ADD docker-entrypoint.sh /usr/bin
ENTRYPOINT ["docker-entrypoint.sh"]