FROM gcc:14 AS builder

RUN apt-get update -y && apt-get install libssl-dev curl
WORKDIR /build
COPY ./src/ .
RUN make
RUN ls
#RUN mkdir rootfs && curl -L 'https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz' | tar -xz -C rootfs

FROM ubuntu:24.04
RUN apt-get update -y && apt-get install -y libssl3 libc6 curl
RUN groupadd -g 22222 potato
WORKDIR /app
COPY --from=builder /build/potato .
#COPY --from=builder rootfs .
COPY userlist .

EXPOSE 222
CMD ["./potato", "server"]
