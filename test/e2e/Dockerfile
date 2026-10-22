# Ubuntu 24.04 with systemd as PID 1, like the production host. The test
# installs CrowdSec from its apt repository once systemd is up, because the
# package setup needs a running systemd.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv dbus curl ca-certificates gnupg \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
