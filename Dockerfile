# 
# docker build -t openisms .
# docker run -it -v <homedir>/openisms_assessments:/srv/openisms/assessments --rm -p 5000:5000 openisms 
#
# Remember that expose the app on the docker ip and port 5000. No security at all.
# 

FROM ubuntu:latest

RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y python-pip
RUN sudo pip install flask
RUN mkdir /srv/openisms

ADD . /srv/openisms/

WORKDIR /srv/openisms
EXPOSE 5000
VOLUME ["assessments"]

ENV SERVER_NAME='0.0.0.0'
ENTRYPOINT ["/usr/bin/python","openisms.py"]
