#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef struct { const char *name; int score; double ratio; } Entry;
static const char *names[] = { "alpha", "beta", "gamma" };   /* needs a rebase */
static Entry table[] = { {"x", 10, 1.5}, {"y", 20, 2.25}, {"z", -5, 0.125} };
static int counter = 41;
static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
static int apply(int (*f)(int), int v) { return f(v); }
static int twice(int v) { return v * 2; }

int main(int argc, char **argv) {
    printf("argc=%d argv[0] ends with '%s'\n", argc, strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0]);
    for (int i = 1; i < argc; i++) printf("  arg %d = %s\n", i, argv[i]);
    for (int i = 0; i < 3; i++) printf("%-6s|%3d|%6.3f|%s\n", table[i].name, table[i].score, table[i].ratio, names[i]);
    printf("fib(20)=%d  apply=%d  counter=%d\n", fib(20), apply(twice, 21), ++counter);
    char *buf = malloc(64); snprintf(buf, 64, "%s-%05d-%x-%c", "id", 42, 255, 'Z');
    printf("buf=%s len=%zu\n", buf, strlen(buf));
    char *a = strdup("hello"); strcat(a = realloc(a, 32), ", world"); printf("%s %d\n", a, strcmp(a, "hello"));
    printf("sqrt(2)=%.6f pow(2,10)=%.1f long=%ld u64=%llu\n", sqrt(2.0), pow(2.0, 10.0), -1234567890123L, 18446744073709551615ULL);
    fprintf(stderr, "this goes to stderr\n");
    return counter - 42;
}
