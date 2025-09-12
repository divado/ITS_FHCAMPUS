
docker run --init \
	   -ti \
	   -p 222:222 \
	   --cap-add=SYS_ADMIN \
	   --security-opt seccomp=unconfined \
	   --security-opt apparmor=unconfined \
	   potato2 $*

