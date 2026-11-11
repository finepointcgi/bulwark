#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy(const char *input) {
    char buf[8];
    strcpy(buf, input);
    buf[8] = 0;
}

int leak(void) {
    char *p = malloc(16);
    if (!p) return 1;
    p[0] = 'a';
    return 0;
}

void use_after_free(void) {
    char *q = malloc(4);
    free(q);
    q[0] = 'x';
}

int uninit(void) {
    int x;
    return x + 1;
}

void log_it(const char *user) {
    char line[64];
    sprintf(line, "user=%s", user);
    printf(user);
    printf("%s", user);
    system(line);
    system("ls");
}
