#!/bin/bash
docker run --detach --tty --rm \
  --name sploitinator \
  --volume /home/myser/sploitinator:/sploitinator:rw \
  --entrypoint /entrypoint.sh \
  snarlysodboxer/kali-linux-sploitinator:latest

