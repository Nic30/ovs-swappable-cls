ip netns exec netns-host1 iperf3 -s
ip netns exec netns-host2 iperf3 -c 192.168.0.1
