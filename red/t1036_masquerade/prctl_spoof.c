/*
 * PRISM Red Team — T1036.005: Match Legitimate Name or Location
 * Demonstrates process name spoofing via prctl(PR_SET_NAME).
 * After this call, /proc/self/comm and ps output show the spoofed name,
 * but /proc/self/exe still points to the real binary path.
 * Detection: compare comm vs. exe basename — mismatch = suspicious.
 *
 * Build: gcc -o /tmp/prctl_spoof prctl_spoof.c
 * Run:   /tmp/prctl_spoof
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <limits.h>

int main(void) {
    char real_exe[PATH_MAX];
    char spoofed_name[] = "kworker/u4:2";   /* Looks like a kernel worker thread */

    /* Read real exe path before spoofing */
    ssize_t len = readlink("/proc/self/exe", real_exe, sizeof(real_exe) - 1);
    if (len > 0) {
        real_exe[len] = '\0';
        printf("[T1036.005] Real exe path:    %s\n", real_exe);
    }

    char comm_before[17] = {0};
    prctl(PR_GET_NAME, comm_before, 0, 0, 0);
    printf("[T1036.005] Comm before spoof: %s\n", comm_before);

    /* Spoof process name — this is what shows in ps, top, /proc/PID/comm */
    if (prctl(PR_SET_NAME, spoofed_name, 0, 0, 0) != 0) {
        perror("[T1036.005] prctl PR_SET_NAME failed");
        return 1;
    }

    char comm_after[17] = {0};
    prctl(PR_GET_NAME, comm_after, 0, 0, 0);
    printf("[T1036.005] Comm after spoof:  %s\n", comm_after);
    printf("[T1036.005] PID: %d — check /proc/%d/comm vs /proc/%d/exe\n",
           getpid(), getpid(), getpid());
    printf("[T1036.005] Sleeping 10s — run: cat /proc/%d/comm && ls -la /proc/%d/exe\n",
           getpid(), getpid());

    sleep(10);

    printf("[T1036.005] Exiting.\n");
    return 0;
}