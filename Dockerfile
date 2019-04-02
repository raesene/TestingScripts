FROM ubuntu:18.04

LABEL maintainer="rorym@mccune.org.uk"

#Java Install based on https://github.com/nimmis/docker-java/blob/master/oracle-8-jdk/Dockerfile

# disable interactive functions
ENV DEBIAN_FRONTEND noninteractive

# set default java environment variable
ENV JAVA_VERSION_MAJOR=8 \
    JAVA_VERSION_MINOR=121 \
    JAVA_HOME=/usr/lib/jvm/default-jvm \
    PATH=${PATH}:/usr/lib/jvm/default-jvm/bin/

#Need Software Properties for add apt repo
RUN apt update && apt-get install -y software-properties-common && rm -rf /var/cache/apt/* && rm -rf /var/lib/apt/lists/*


RUN add-apt-repository ppa:webupd8team/java -y && \
    echo debconf shared/accepted-oracle-license-v1-1 select true |  debconf-set-selections && \
    echo debconf shared/accepted-oracle-license-v1-1 seen true |  debconf-set-selections && \
    apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y --no-install-recommends oracle-java8-installer && \
    apt-get install -y --no-install-recommends oracle-java8-set-default && \
    apt-get install -y libxext6 libxrender1 libxtst6 libxi6 && \
    rm -rf /var/cache/oracle-jdk8-installer && \
    ln -s java-8-oracle  /usr/lib/jvm/default-jvm && \
    rm -rf /var/cache/apt/* && rm -rf /var/lib/apt/lists/*

#Get Burp
RUN mkdir burp
WORKDIR /burp
RUN wget -q -O burpsuite.jar https://portswigger.net/burp/releases/download?product=community\&version=1.7.35\&type=jar

RUN mkdir -p /root/.java/.userPrefs/burp/

COPY prefs.xml /root/.java/.userPrefs/burp/


ENTRYPOINT ["java", "-jar", "/burp/burpsuite.jar"]