FROM python:3-alpine

MAINTAINER Garrett Crosby "garrett.crosby@sharpspring.com"

WORKDIR /app

COPY ./requirements.txt /requirements.txt

RUN pip3 install -r requirements.txt

COPY . /
