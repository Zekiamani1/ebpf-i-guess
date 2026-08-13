#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

int main(void) {
    fprintf(stderr, "pid=%d  (harusnya ~100 ok, sisanya EAGAIN tiap detik)\n", getpid());
    for (int sec = 0; sec < 5; sec++) {
        unsigned long ok = 0, eagain = 0, other = 0;
        unsigned long long t0 = now_ns();
        do {
            if (write(1, ".", 1) >= 0)
                ok++;
            else if (errno == EAGAIN)
                eagain++;
            else
                other++;
        } while (now_ns() - t0 < 1000000000ULL);
        fprintf(stderr, "detik %d: ok=%lu eagain=%lu error_lain=%lu\n", sec, ok, eagain, other);
    }
    return 0;
}
