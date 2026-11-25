# Throwaway device stand-in for tests/test_sudo_real.py: a real sshd and a real sudo (Debian 13,
# what a virtual device runs), no terminal. Never deployed; the test starts and removes it.
ARG BASE=debian:trixie-slim
FROM ${BASE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends sudo openssh-server zsh >/dev/null \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /opt/fake
COPY k3s /usr/local/bin/k3s
COPY setup.sh /opt/fake/setup.sh
RUN chmod 0755 /usr/local/bin/k3s /opt/fake/setup.sh
