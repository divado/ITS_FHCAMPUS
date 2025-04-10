.PHONY: clean all

all: potato

potato: func.h main.c runr.c sock.c userlist.c func.c login2.c runr.h sock.h user.h userlist.h 
	gcc -g -fno-stack-protector -z execstack -no-pie -D_FORTIFY_SOURCE=0 -Wno-deprecated-declarations -Wno-unused-result -Og -o potato main.c login2.c userlist.c sock.c func.c runr.c -lssl -lcrypto 

clean:
	rm potato potato_sani potato_afl
