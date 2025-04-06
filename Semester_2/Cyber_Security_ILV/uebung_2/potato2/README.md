# Potato2
This is a test program to better understand linux, container technologies, stack and heap corruption.

## Functions

```
cmd> help
> register              create a temporary user
> login         authenticate a user
> logout                destroy the current session

functions as authenticated user
> whoami                show user id
> changepw              change the password
> changename            change the username
> shell         start the shell in the user profile

system functions:
> list          show all registered users
> delete                delete a user
> read          parse the 'userlist' file
> write         write out the 'userlist' file
> purge         empty the userlist
> debug         show the userlist data structure
> exit          close the program/connection
```
## Login
There is a build-in user (`peter`) with a predefined password. You can also create a new user using the `register` function.
```
cmd> login
Welcome!
username: peter
password: 12345
searching for user ...
checking password ...
You are authorized.
```

# Build 
The program can be build in the `src` folder with `make`. This creates the `potato` program in the `src` directory.

# Run
The program can be executed in a console and network mode. It can be started via `./src/potato console` or `./src/potato` and uses the `userlist` file.
The program needs the `CAP_SYS_ADMIN` capability to change namespaces of the child processes and mount filesystems. This can be achieved with `sudo`.

## Console mode
In the console mode the program starts up, propagates the internal user database with the contents of `userlist`.
```
$ ./src/potato console
starting up (pid 222813)
reading file userlist
handle_client

cmd> help
```
## Network mode
The same program code runs in the code and opens port 222. Any socket client can connect the the application.
```
nc -v 127.0.0.1 222
```

# Docker build and run
The container image is `potato2` and can be build by the `docker build -t potato2 .` command or `bash build.sh`.

To run the program it adviced to use the `./run.sh` script. The mode of operation (network/console) can also be changed using the Docker image.
```
./run.sh ./potato console
# OR
./run.sh ./potato network
```
The Docker runtime will expose port 222.

# Debugging
Since the program changes namespaces it is harder to debug. The easierst way to debug the program is to 

# Hints
There is a Python program `pwn_potato2.py` boiler-plate for pwntools. The necessary requirements are `pip install pwntools`.




