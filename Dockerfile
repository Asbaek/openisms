# To build and run
# docker build -t openisms .
# docker run -it --rm -p 5000:5000 -v `pwd`/assessments:/srv/openisms/assessments openisms
#
# While developing
# docker run -it --rm -p 5000:5000 -v `pwd`:/srv/openisms -e DEBUG=true openisms

FROM ubuntu:latest

RUN apt-get update && \
  apt-get dist-upgrade -y && \
  apt-get install -y python-pip && \
  pip install flask
RUN mkdir /srv/openisms

ADD . /srv/openisms/

WORKDIR /srv/openisms
EXPOSE 5000
VOLUME ["assessments"]

ENV HOSTNAME=0.0.0.0
ENTRYPOINT ["/usr/bin/python", "openisms.py"]
