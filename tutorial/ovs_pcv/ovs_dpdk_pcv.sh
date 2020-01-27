# http://docs.openvswitch.org/en/latest/intro/install/dpdk/
# http://docs.openvswitch.org/en/latest/topics/dpdk/bridge/#quick-example
# https://access.redhat.com/documentation/en-us/red_hat_openstack_platform/11/html/network_functions_virtualization_planning_and_prerequisites_guide/assembly_ovsdpdk_parameters
cd /usr/src/
sudo wget https://fast.dpdk.org/rel/dpdk-19.11.tar.xz
sudo tar xf dpdk-19.11.tar.xz
export DPDK_DIR=/usr/src/dpdk-19.11
cd $DPDK_DIR

export DPDK_TARGET=x86_64-native-linuxapp-gcc
export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
make install T=$DPDK_TARGET DESTDIR=install

export LD_LIBRARY_PATH=$DPDK_DIR/x86_64-native-linuxapp-gcc/lib

git clone https://github.com/Nic30/pclass-vectorized.git
pushd pclass-vectorized
mkdir -p build/default
meson build/default
pushd build/default
ninja
sudo ninja install
popd
popd

git clone https://github.com/openvswitch/ovs.git
cd ovs
./boot.sh
./configure --with-dpdk=$DPDK_BUILD
sudo make install

export PATH=$PATH:/usr/local/share/openvswitch/scripts
export DB_SOCK=/usr/local/var/run/openvswitch/db.sock

sudo mkdir -p /usr/local/var/run/openvswitch
sudo mkdir -p /usr/local/etc/openvswitch

sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db
# https://stackoverflow.com/questions/28506053/open-vswitch-database-connection-failure-after-rebooting
sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                     --private-key=db:Open_vSwitch,SSL,private_key \
                     --certificate=db:Open_vSwitch,SSL,certificate \
                     --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                     --pidfile --detach

sudo ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
sudo ovs-vsctl --no-wait set Open_vSwitch . \
    other_config:dpdk-socket-mem="1024,0"

sudo ovs-vsctl get Open_vSwitch . dpdk_initialized

sudo ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev
sudo ovs-vsctl set bridge br0 datapath_type=netdev \
  protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14

sudo ovs-ofctl -O OpenFlow14 dump-ports br0
ovs-appctl dpif-netdev/pmd-stats-show
# ovs-vsctl --no-wait set Open_vSwitch . other_config:smc-enable=true
# ovs-vsctl set interface <iface> other_config:emc-enable=true

#ovs-vsctl add-port br0 dpdk-p0 \
#   -- set Interface dpdk-p0 type=dpdk options:dpdk-devargs=0000:01:00.0

# ovs-vsctl add-port br0 null0 -- set Interface null0 type=dpdk \
#    options:dpdk-devargs=eth_null0

