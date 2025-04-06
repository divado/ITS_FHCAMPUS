#pragma once

#define USERNAME_LENGTH 50
#define PASSWORD_LENGTH 50

struct _user
{
     char name[20];
     char password_hash[32]; // md5
     int id;
     int gid;
     char home[50];
     char shell[50];
} typedef t_user;

void print_user(t_user* user);
int check_password(t_user* user, char* password);
char *str2md5(const char *str, int length);
int is_authenticated();
int is_privileged();
