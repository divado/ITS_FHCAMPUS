
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
// waitpid
#include <sys/types.h>
#include <sys/wait.h>

#include "sock.h"

#define PORT 222
#define BACKLOG 5
#define MAXCONN 100

int server_fd;
struct sockaddr_in server_addr;

int start_server(void (*handle_conn_func)()) // returns the listening socket
{
    int client_fd;
    pid_t pid = -1;
    int option = 1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, BACKLOG) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while(client_fd = next_client()) // command line loop
    {
	pid = fork();
        if(pid < 0) {
            printf("fork error");
            break;
        } else if (pid == 0) { // child
            close(server_fd);
	    dup2(client_fd, STDIN_FILENO);
            dup2(client_fd, STDOUT_FILENO);
            dup2(client_fd, STDERR_FILENO);
            close(client_fd);
            handle_conn_func();
	    fclose(stdin);
	    fclose(stdout);
	    fclose(stderr);
	    exit(0);
        } else { // parent 
            close(client_fd);
	}
	// Optionally, clean up zombie processes
        while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    return server_fd;
} 

int next_client()
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd == -1) {
        perror("Accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    return client_fd;
}

void stop_server()
{
    // you need to close the client_fds yourself
    close(server_fd);
}

void close_client(int client_fd)
{
    shutdown(STDOUT_FILENO, SHUT_WR);
}
