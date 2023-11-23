FROM ubuntu:20.04
## Iredapd version 5.3.3

RUN apt update -y
RUN apt install -y python3-mysqldb python3-sqlalchemy python3-webpy python3-pymysql python3-pip patch

#RUN pip install beaker

RUN mkdir /opt/iredapd

WORKDIR /opt/iredapd

COPY . /opt/iredapd
RUN cp iredapd.debian /etc/init.d/iredapd
RUN chmod 0755 /etc/init.d/iredapd
RUN useradd -m -d /home/iredapd -s /sbin/nologin iredapd
RUN mkdir /var/log/iredapd/
RUN touch /var/log/iredapd/iredapd.log
RUN chown iredapd:iredapd -R /var/log/iredapd/
# mount volume /opt/iredapd/settings.py

RUN apt install vim net-tools -y

COPY scripts/* /home/
RUN chmod a+x /home/*
EXPOSE 7777
WORKDIR /home
ENTRYPOINT ["./entrypoint.sh"]
