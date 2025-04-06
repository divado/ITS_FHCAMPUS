
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <grp.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>

#include "runr.h"

#define errExit(msg)    do { fprintf(stderr, msg); exit(EXIT_FAILURE); \
                        } while (0)

static int 
child_func(void *arg)
{
    char *envp[] = {NULL};             // discard env
    struct stat st = {0};
    t_runr_args *runr_args = (t_runr_args *)arg;
    //system("/bin/sh");

    fprintf(stderr, "alive id=%d gid=%d shell=%s\n", runr_args->id,
		    				     runr_args->gid,
						     runr_args->proc);

    fprintf(stderr, "mount-MS_PRIVATE\n");
    if (mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL) == -1)
    {
        errExit("mount-MS_PRIVATE");
        exit(1);
    }

    // remount proc to see the current pid namespace in /proc
    /* not allowed in SLAVE
    if(umount2("/proc", MNT_FORCE) == -1)
    {
        errExit("umount");
    }
    */
    fprintf(stderr, "proc\n");

    if (mount("proc", "/proc", "proc", 0, NULL) == -1)
    {
        errExit("mount");
    }

    // home dir
    fprintf(stderr, "home\n");
    if (stat(runr_args->home, &st) == -1) // home must exist
    {
         mkdir(runr_args->home, 0700);
    }
    // set persmissions and chdir into it
    chown(runr_args->home,  
	  runr_args->id, 
	  runr_args->gid);

    chdir(runr_args->home);

    // add CAP_NET_RAW and CAP_NET_BIND_SERVICE

    fprintf(stderr, "groups\n");
    // remove all groups
    if(setgroups(0, NULL) < 0) {
         errExit("can't remove groups. need sudo."); 
         return -1; 
    }; 
    // change the uid and gid
    if(setresgid(runr_args->gid,
                 runr_args->gid, 
                 runr_args->gid) < 0) { 
         errExit("can't setresgid. need sudo.");
         return -1; 
    }; 
    if(setresuid(runr_args->id, 
                 runr_args->id, 
                 runr_args->id) < 0) {
         errExit("can't setresuid. need sudo."); 
         return -1; 
    };

    fprintf(stderr, "exec %s\n", runr_args->proc);
    char* exec_args[] = {runr_args->proc, 0};
    execve(exec_args[0], exec_args, envp);     // Execute shell
}

pid_t
runr_start(t_runr_args *arg)
{
    fprintf(stderr, "runr id=%d gid=%d shell=%s\n", arg->id,
		    				     arg->gid,
						     arg->proc);
    pid_t pid = -1;
    char *stack = mmap(NULL,
                       STACK_SIZE,
                       PROT_READ | PROT_WRITE,  // rw-
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, // private stack, not shared
                       -1,
                       0);
    if (stack == MAP_FAILED)
    {
        errExit("mmap");
        exit(1);
    }
    // need to fork for unshare
    // https://lwn.net/Articles/531419/
    if ((pid = clone(child_func,         // called routine
        	     stack + STACK_SIZE,      // stack top
        	     CLONE_NEWNS | CLONE_NEWPID | SIGCHLD,  //
        	     arg)) == -1)            // function argument
    {
        errExit("clone failed.");
        exit(1);
    }

    return pid; // TODO return rc
}
