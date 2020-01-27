make -j10
sudo ovs-vsctl del-br br0 2>/dev/null
OVS_SCRIPTS=/usr/share/openvswitch/scripts/
sudo $OVS_SCRIPTS/ovs-ctl stop
sudo rmmod openvswitch

sudo make install
sudo make modules_install
sudo modprobe openvswitch
UUID="8041392a-6c95-44a6-a5e2-2bfd6a4a86b4"
sudo $OVS_SCRIPTS/ovs-ctl start --system-id=$UUID

# Run command inside network namespace
as_ns () {
    NAME=$1
    NETNS=netns-${NAME}
    shift
    sudo ip netns exec ${NETNS} $@
}

# Create network namespace
create_ns () {
    NAME=$1
    IP=$2
    NETNS=netns-${NAME}
    sudo ip netns del ${NETNS} 2> /dev/null
    sudo ip netns add ${NETNS}
    sudo ip link add dev veth-${NAME} type veth peer name veth0 netns ${NETNS}
    sudo ip link set dev veth-${NAME} up
    as_ns ${NAME} ip link set dev lo up
    [ -n "${IP}" ] && as_ns ${NAME} ip addr add dev veth0 ${IP}
    as_ns ${NAME} ip link set dev veth0 up
}

create_ns host1 192.168.0.1/24
create_ns host2 192.168.0.2/24

sudo ovs-vsctl add-br br0 \
-- set bridge br0 other-config:datapath-id=0000000000000001 \
-- set bridge br0 other-config:disable-in-band=true \
-- set bridge br0 fail_mode=secure \
-- add-port br0 veth-host1 -- set interface veth-host1 ofport_request=1 \
-- add-port br0 veth-host2 -- set interface veth-host2 ofport_request=2 \
-- set-controller br0 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654

