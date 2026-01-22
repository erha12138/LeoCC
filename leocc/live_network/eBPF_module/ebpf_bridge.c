#include <linux/module.h>
#include <linux/export.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <linux/ktime.h>

static int reconf_state;
static ktime_t last_signal_time;
#define HOLD_DURATION_MS 50

int get_state(void) 
{
    int current_s = READ_ONCE(reconf_state);
    
    if (current_s != 0) {
        s64 delta = ktime_ms_delta(ktime_get(), last_signal_time);
        if (delta >= HOLD_DURATION_MS) { // lazy expiration
            WRITE_ONCE(reconf_state, 0);
            return 0;
        }
    }
    return current_s;
}
EXPORT_SYMBOL_GPL(get_state);

void set_state(u32 mark) 
{
    int new_val = (int)(mark & 0xFFFF);
    ktime_t now = ktime_get();

    if (new_val != 0) {
        WRITE_ONCE(reconf_state, new_val);
        WRITE_ONCE(last_signal_time, now);
    } else {
        int current_s = READ_ONCE(reconf_state);
        if (current_s != 0) {
            s64 delta = ktime_ms_delta(now, last_signal_time);
            if (delta >= HOLD_DURATION_MS) {
                WRITE_ONCE(reconf_state, 0);
            }
        }
    }
}

static unsigned int my_nf_ingress(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    if (skb && ip_hdr(skb) && ip_hdr(skb)->protocol == IPPROTO_TCP) set_state(skb->mark);    
    return NF_ACCEPT;
}

static struct nf_hook_ops nfops = {
    .hook     = my_nf_ingress,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init bridge_init(void)
{
    return nf_register_net_hook(&init_net, &nfops);
}
static void __exit bridge_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfops);
}
module_init(bridge_init);
module_exit(bridge_exit);
MODULE_LICENSE("GPL");