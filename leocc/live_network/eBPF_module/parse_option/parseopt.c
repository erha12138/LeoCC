#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "parseopt.skel.h" 
#include <net/if.h>

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main()
{
    struct parseopt_bpf *skel;
    int err;
    bool hook_created = false;

    const char *ifname = ""; // interface name
    int ifindex = if_nametoindex(ifname);

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
        .handle = 1,
        .priority = 1);

    libbpf_set_print(libbpf_print_fn);

    skel = parseopt_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load eBPF skeleton\n");
        return 1;
    }

    err = bpf_tc_hook_create(&tc_hook);
    if (!err)
        hook_created = true;
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %d\n", err);
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Failed to set signal handler: %s\n", strerror(errno));
        err = errno;
        goto cleanup;
    }

    printf("Successfully attached Program Parse Option! Press Ctrl+C to exit...\n");

    while (!exiting) {
        sleep(1);
    }

    tc_opts.flags = 0;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err)
        fprintf(stderr, "Failed to detach TC program: %d\n", err);

cleanup:
    if (hook_created)
        bpf_tc_hook_destroy(&tc_hook);
    parseopt_bpf__destroy(skel);
    return err != 0;
}
