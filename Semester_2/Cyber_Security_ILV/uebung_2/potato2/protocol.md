# Stack Corruption

Student: Philip Magnus

The steps in this writeup were performed on a Ubuntu 24.04 LTS (x64) system.

## Building potato

For the building process the following packages have been installed. `pipx` is technically not used for the build process but the installation of `pwntools` a Python library enabling us to execute the attacks.

```bash
$ sudo apt install libssl-dev gcc gcc-multilib pipx -y
```

To install the *GDB Enhanced Features* suite (GEF) the following `curl` command was used.

```bash
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Next the source files for potato2 were checked out with its git repository.

```bash
$ git clone https://github.com/edgecase1/potato2.git
```

Using the following `Makefile` two binaries have been build to run the attacks against in the subsequent steps.

```make
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires installation of gcc multilib
# sudo apt install gcc-multilib for m32

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
# turn on optimizations to get some ROP gadgets
DEBUG_OPTS_ROP=-ggdb3 -O2
INCLUDES=-Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Isrc
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)
# include glibc statically to get additional gadgets
CCOPTS4ROP = -static $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS_ROP) $(INCLUDES) $(DEFINES)

CFILES = \
	src/main.c \
	src/runr.c \
	src/sock.c \
	src/userlist.c \
	src/func.c \
	src/login2.c

HFILES = \
	src/runr.h \
	src/sock.h \
	src/user.h \
	src/userlist.h 

.PHONY: clean all

all: potato potato_rop

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc $(CCOPTS) -o potato $(CFILES) -Lopenssl  -lssl -lcrypto 

# binary for ROP attack
potato_rop: $(CFILES) $(HFILES)
	gcc $(CCOPTS4ROP) -o potato_rop $(CFILES) -Lopenssl  -lssl -lcrypto 

clean:
	rm -f potato potato_rop
```

The `potato` and `potato_rop` files were built using the `make` command.

```bash
$ make

gcc -Wno-deprecated-declarations -Wno-unused-result -fno-stack-protector -z execstack -no-pie -ggdb3 -O0 -Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src -D_FORTIFY_SOURCE=0 -o potato src/main.c src/runr.c src/sock.c src/userlist.c src/func.c src/login2.c -Lopenssl  -lssl -lcrypto
gcc -static -Wno-deprecated-declarations -Wno-unused-result -fno-stack-protector -z execstack -no-pie -ggdb3 -O2 -Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src -D_FORTIFY_SOURCE=0 -o potato_rop src/main.c src/runr.c src/sock.c src/userlist.c src/func.c src/login2.c -Lopenssl  -lssl -lcrypto
```

The `potato` executables can now be used as follows.

```bash
$ ./potato

./potato console
./potato server
```

To enable our Python scripts to run attacks against the `potato` binaries as well as starting the debugger and many more QoL features `pwntools` was installed using `pipx`.

```bash 
$ pipx install pwntools
```

`pipx` automatically manages Python `venvs` and allows for an easy way to install `pip` packages globally.

## Scanning for vulnerabilities

**TODO**

Instead of looking through the code manually the code was scanned for a list of functions, vulnerable to buffer overflows, using [ripgrep](https://github.com/BurntSushi/ripgrep) `rg` for short. `rg` scans all files in a directory, including sub-directories, for a given string and outputs the file in which the string was found as well as the line containing the string and the corresponding line number.

```bash
$ rg -w -n \
  -e "gets" \
  -e "strcpy" \
  -e "strcat" \
  -e "sprintf" \
  -e "vsprintf" \
  -e "scanf" \
  -e "fscanf" \
  -e "sscanf" \
  -e "memcpy" \
  -e "memmove" \
  -e "strtok"
  
func.c
60:    scanf("%d", &id);
187:    fscanf(stdin, "%s", input_username); // TODO security

userlist.c
240:    token = strtok(line, ":");
246:                strcpy(parsed_user->name, token);
257:                    strcpy(parsed_user->home, token);
260:                    strcpy(parsed_user->shell, token);
266:       token = strtok(NULL, ":");

login2.c
43:    strcpy(user->name, username);
44:    sprintf(user->home, "/home/%s", username);
45:    strcpy(user->shell, "/usr/bin/rbash");

```

The `fscanf` function on line 187 in the *func.c* file looks like a prime candidate that can be used for a buffer overflow. The string read from `stdin` is not limited by any size and thus can be used to write over the given buffer size of `input_username`, which is 50 bytes, directly onto the stack. This can be used to write a maliciously chosen address to the stack to redirect the execution flow of the program.

```C
void change_name() {
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}
```

## Debugging

**TODO**

### Environment Setup