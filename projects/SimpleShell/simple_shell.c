/**
 * @brief This file implements a simple shell that can execute commands using either fork or system.
 *
 * @author Amir Varkovitzky
 * @date 06-07-2025
 */

#include "simple_shell.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define CMD_BUF_SIZE 256

int simple_shell_interactive(void)
{
    char input[16];
    run_mode_t mode = RUN_MODE_FORK;
    printf("Choose run mode ([f]ork/[s]ystem): ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin))
    {
        if (input[0] == 's' || input[0] == 'S')
            mode = RUN_MODE_SYSTEM;
    }
    printf("Running simple shell in %s mode. Type 'exit' to quit.\n",
           mode == RUN_MODE_FORK ? "fork" : "system");
    return simple_shell(mode);
}

#include <signal.h>
#include <errno.h>

void handle_signal(int signo)
{
    if (signo == SIGINT)
    {
        printf("\nrecieved SIGINT\nsimple_shell> ");
        fflush(stdout);
    }
}

static int handle_builtin(char **argv)
{
    if (strcmp(argv[0], "cd") == 0)
    {
        if (argv[1] == NULL)
        {
            fprintf(stderr, "simple_shell: expected argument to \"cd\"\n");
        }
        else
        {
            if (chdir(argv[1]) != 0)
            {
                perror("simple_shell");
            }
        }
        return 1;
    }
    return 0;
}

static int run_command_fork(char **argv)
{
    pid_t pid;
    int status = 0;
    
    pid = fork();
    if (pid < 0)
    {
        perror("fork failed");
        return -1;
    }
    if (pid == 0)
    {
        /* Child process: restore default SIGINT */
        signal(SIGINT, SIG_DFL);
        execvp(argv[0], argv);
        perror("execvp failed");
        exit(127);
    }
    
    if (waitpid(pid, &status, 0) < 0)
    {
        perror("waitpid failed");
        return -1;
    }
    return status;
}

static int run_command_system(const char *cmd)
{
    int ret = system(cmd);
    if (ret == -1)
    {
        perror("system failed");
    }
    return ret;
}

int simple_shell(run_mode_t mode)
{
    char cmd[CMD_BUF_SIZE];
    char *argv[CMD_BUF_SIZE / 2 + 1];
    int ret;
    int argc;
    char *token;

    /* Ignore SIGINT in the shell, let user handle it or reprint prompt */
    signal(SIGINT, handle_signal);

    while (1)
    {
        printf("simple_shell> ");
        fflush(stdout);
        if (!fgets(cmd, sizeof(cmd), stdin))
        {
            printf("\nEOF received, exiting.\n");
            break;
        }
        /* Remove trailing newline */
        cmd[strcspn(cmd, "\n")] = '\0';
        
        if (strlen(cmd) == 0) continue;

        if (strcmp(cmd, "exit") == 0)
        {
            printf("Exiting simple shell.\n");
            break;
        }

        /* Parse arguments for built-in check */
        argc = 0;
        /* We need a copy of cmd for system() mode but we parse it anyway for builtins */
        char cmd_copy[CMD_BUF_SIZE];
        strncpy(cmd_copy, cmd, CMD_BUF_SIZE);
        cmd_copy[CMD_BUF_SIZE-1] = '\0';

        token = strtok(cmd_copy, " \t\n");
        while (token && argc < (int)(sizeof(argv) / sizeof(argv[0])) - 1)
        {
            argv[argc++] = token;
            token = strtok(NULL, " \t\n");
        }
        argv[argc] = NULL;

        if (argc > 0 && handle_builtin(argv))
        {
            continue; /* Builtin executed */
        }

        ret = 0;
        if (mode == RUN_MODE_FORK)
            ret = run_command_fork(argv);
        else
            ret = run_command_system(cmd); /* use original cmd string for system() */
            
        if (ret != 0 && ret != 127 && ret != 32512) /* 32512 is 127<<8 (exit code 127) */
        {
             /* Don't print for every non-zero, standard shells don't */
        }
    }
    return 0;
}
