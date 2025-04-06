
static int child_func(void *arg);

struct _start_proc_args
{
    char* home;
    int id;
    int gid;
    char proc[50];
} typedef t_runr_args;

pid_t runr_start(t_runr_args *arg);

#define STACK_SIZE (1024*1024)
