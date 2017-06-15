FROM centos:centos6.6
MAINTAINER  wushang  "wushang126@163.com"
# ¸üÐÂÔ´

COPY jdk-6u45-linux-x64-rpm.bin /opt/jdk-6u45-linux-x64-rpm.bin
COPY jenkins-war-1.514.war /root/jenkins-war-1.514.war
RUN cd /opt && chmod 777 /opt/* && ./jdk-6u45-linux-x64-rpm.bin
RUN rm -rf /opt/*


EXPOSE 8080 54623

ENTRYPOINT cd /root/ && java -jar jenkins-war-1.514.war
