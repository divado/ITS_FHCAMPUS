#pragma once

#include "user.h"

// linked list to store users
struct _user_list_element 
{
     struct _user_list_element * next;
     t_user* user;
} typedef t_user_list_element;

struct _user_list 
{
     t_user_list_element* head;
     int number_of_elements;
} typedef t_user_list;

t_user* get_user_by_name(char* username);
int delete_user_by_id(int id);
void print_debug(int i, t_user_list_element* element);
void print_list_element(int row_nr, t_user_list_element* element);
void walk_list(void (*func)());
t_user_list_element* add_user_to_list(t_user* new_user);
void read_list(char* path);
void write_list(char* path);
void purge_list();
t_user_list_element* get_last_element();
int next_free_id();
t_user* parse_userlist_list(char* line);
void init_userlist();
t_user* new_user(char* username, char* password);
