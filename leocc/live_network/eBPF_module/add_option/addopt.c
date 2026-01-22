#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "addopt.skel.h"
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <sys/time.h>

#define THRSHOLD_MS 45
#define HOLD_DURATION_MS 100

static volatile sig_atomic_t exiting = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <POP_IP>\n", argv[0]);
        return 1;
    }

    struct addopt_bpf *skel;
    int err;
    bool hook_created = false;
    const char *ifname = ""; // interface name
    int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr, "Error, cannot find interface %s\n", ifname);
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
        .handle = 1,
        .priority = 1);

    libbpf_set_print(libbpf_print_fn);

    skel = addopt_bpf__open_and_load();
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

    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_egress);
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

    printf("Successfully attached! Now updating reconf_state...\n");

    int map_fd = bpf_map__fd(skel->maps.reconf_state);
    __u64 last_timestamp_ms = 0, last_trigger_time_ms = 0;
    char cmd[256], buffer[256];
    snprintf(cmd, sizeof(cmd), "ping -D -i 0.01 %s", argv[1]);
    FILE *ping_output = popen(cmd, "r");
    if (!ping_output) {
        perror("popen");
        return 1;
    }
			
    __u32 key = 0, val = 0;
    while (fgets(buffer, sizeof(buffer), ping_output)) {
        if (exiting) break;
        char *ts_str = strstr(buffer, "[");
        if (ts_str) {
            ts_str += strlen("[");
            char *ts_end = strstr(ts_str, "]");
            *ts_end = '\0';
            __u64 current_timestamp_ms = (__u64)(atof(ts_str) * 1000);
            
            if (last_timestamp_ms && current_timestamp_ms - last_timestamp_ms > THRSHOLD_MS) {
                val = 1; 
                bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
                last_trigger_time_ms = current_timestamp_ms;
            } else {
                int current_map_val = 0;
                if (bpf_map_lookup_elem(map_fd, &key, &current_map_val) == 0) {
                    if (current_map_val == 1) {
                        if (current_timestamp_ms - last_trigger_time_ms > HOLD_DURATION_MS) {
                            val = 0; 
                            bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
                        }
                    }
                }
            }
            last_timestamp_ms = current_timestamp_ms;
            fflush(stdout);
        }
    }

    pclose(ping_output);
    tc_opts.flags = 0;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err)
        fprintf(stderr, "Failed to detach TC program: %d\n", err);

cleanup:
    if (hook_created)
        bpf_tc_hook_destroy(&tc_hook);
    addopt_bpf__destroy(skel);
    return err != 0;
}

