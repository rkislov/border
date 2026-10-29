FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends strongswan-charon strongswan-swanctl libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins strongswan-pki iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["/usr/lib/ipsec/charon"]
