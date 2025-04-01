#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <string.h>

#define MAX_ARGS 32
#define RESTART_DELAY 1  // 重启等待时间（秒）

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

void log_message(const char* message) {
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    timestamp[strlen(timestamp)-1] = '\0'; // 去除换行符
    printf("[%s] %s\n", timestamp, message);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    char* target_args[MAX_ARGS];
    int i;
    for (i = 1; i < argc && i < MAX_ARGS; i++) {
        target_args[i-1] = argv[i];
    }
    target_args[i-1] = NULL;

    pid_t pid;
    int status;
    
    log_message("Monitor started");

    while (keep_running) {
        log_message("Starting target program...");
        pid = fork();
        
        if (pid == 0) { // 子进程
            execvp(target_args[0], target_args);
            // 如果execvp失败
            perror("execvp");
            exit(EXIT_FAILURE);
        } 
        else if (pid > 0) { // 父进程
            // 等待子进程退出
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status)) {
                log_message("Target program exited normally");
                if (WEXITSTATUS(status) == 0) {
                    log_message("Program exited successfully, monitor exiting");
                    break;
                }
                log_message("Program exited with error code, restarting...");
            }
            else if (WIFSIGNALED(status)) {
                int term_signal = WTERMSIG(status);
                char msg[256];
                snprintf(msg, sizeof(msg), 
                        "Program crashed with signal %d (%s), restarting...",
                        term_signal, strsignal(term_signal));
                log_message(msg);
            }
            
            // 等待指定时间后重启
            sleep(RESTART_DELAY);
        }
        else {
            perror("fork");
            exit(EXIT_FAILURE);
        }
    }

    // 清理并退出
    log_message("Monitor shutting down");
    if (pid > 0) {
        kill(pid, SIGTERM); // 确保子进程终止
    }
    return EXIT_SUCCESS;
}