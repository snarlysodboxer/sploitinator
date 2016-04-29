FROM snarlysodboxer/kali-linux:latest
MAINTAINER david amick <docker@davidamick.com>

RUN ["/bin/bash", "-c", "apt-get update -qq && apt-get install -qy metasploit-framework git-core nmap"]

ENTRYPOINT ["/bin/bash"]
CMD ["-l"]
