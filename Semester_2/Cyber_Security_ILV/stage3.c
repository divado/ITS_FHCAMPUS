#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
  /* set up command buffer */
  char cmdbuf[128] = "/usr/bin/file ";
  char *input = cmdbuf + strlen(cmdbuf);
  int len = sizeof(cmdbuf) - (strlen(cmdbuf) + 1);


  gid_t egid = getegid();
  setregid(egid, egid);

  /* read input -- use safe function to prevent buffer overrun */
  fprintf(stdout, "Please enter the filename you want to access: ");
  fgets(input, len, stdin);
  input[strcspn(input, "\r\n")] = 0;

  struct stat buffer;
  int exist = stat(input,&buffer);
  if(exist == 0) {
    /* execute command */
    system(cmdbuf);
  } else {
    fprintf(stdout, "Your file does not exist!\n");
    return 1;
  }

  return 0;

}