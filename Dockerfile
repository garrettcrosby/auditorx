FROM ubuntu:latest

MAINTAINER Garrett Crosby "garrett.crosby@sharpspring.com"

COPY . /app
WORKDIR /app

RUN apt-get update \
  && apt-get install -y python3-pip python3-dev \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip

RUN pip3 install -r requirements.txt

RUN ["chmod", "+x", "/app/setup.sh"]
RUN /app/setup.sh

CMD ["python3", "/app/main.py"]
