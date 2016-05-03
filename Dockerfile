FROM kalilinux/kali-linux-docker:latest
MAINTAINER david amick <docker@davidamick.com>

RUN ["/bin/bash", "-c", "apt-get update -qq && apt-get install -qy ruby postgresql metasploit-framework git-core nmap"]
RUN ["/bin/bash", "-c", "echo 'host    all             postgres             127.0.0.1/32            trust' >> /etc/postgresql/9.5/main/pg_hba.conf"]

RUN ["mkdir", "/sploitinator"]
ENTRYPOINT ["/bin/bash"]
CMD ["-l"]

COPY sploit entrypoint.sh /
