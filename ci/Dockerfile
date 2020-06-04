FROM ubuntu:16.04

MAINTAINER infrastructure@zensystem.io

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Get Ubuntu packages
RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential curl \
       gcc-mingw-w64-x86-64 gosu maven openjdk-8-jdk=8u252-b09-1~16.04 \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && apt-get -y clean \
    && apt-get -y autoclean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

