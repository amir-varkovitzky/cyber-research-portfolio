/*
 * simple_shell.h - Simple Shell API
 *
 * Provides entry points for a custom Unix shell implementation.
 * Supports interactive mode and command execution via fork/exec or system().
 *
 * Usage:
 *   1. Call simple_shell_interactive() to start the REPL loop.
 *   2. Or call simple_shell() with a specific mode.
 */

#ifndef SIMPLE_SHELL_H
#define SIMPLE_SHELL_H

/* Execution modes for the shell */
typedef enum {
    RUN_MODE_FORK,   /* Use fork() + execvp() */
    RUN_MODE_SYSTEM  /* Use system() */
} run_mode_t;

/**
 * @brief Starts the shell main loop.
 * @param mode The execution mode to use (FORK or SYSTEM).
 * @returns Exit status code.
 */
int simple_shell(run_mode_t mode);

/**
 * @brief Starts the shell in interactive mode (prompts user for inputs).
 * @returns Exit status code.
 */
int simple_shell_interactive(void);

#endif /* SIMPLE_SHELL_H */
