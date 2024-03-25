FROM ubuntu:18.04

RUN apt update &&\
	apt install -y libssl1.1 libssl1.0.0 libssl1.0-dev socat

COPY ./flag /flag
COPY ./insosystems /insosystems

RUN mkdir /uploads/

EXPOSE 5556

ENTRYPOINT ["socat", "TCP4-LISTEN:5556,reuseaddr,fork", "EXEC:/insosystems"]
