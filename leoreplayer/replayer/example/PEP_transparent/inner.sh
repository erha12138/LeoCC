DIR=$(cd "$(dirname "$0")"; pwd)
DEV=ingress

tcpdump -i $DEV -s 66 -w $DIR/inner.pcap &
CAP=$!

iperf3 -c 100.64.0.1 -p 9999 -C $2 -t $1

kill $CAP
