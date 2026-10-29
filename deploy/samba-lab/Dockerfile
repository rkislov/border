FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision winbind krb5-user ldap-utils python3 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["samba", "--foreground", "--no-process-group"]
