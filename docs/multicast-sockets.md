# Multicast socket isolation

Different LiDAR multicast groups may share a UDP destination port. On Linux,
joining a group alone does not isolate a wildcard-bound socket: the default
`IP_MULTICAST_ALL=1` permits delivery for groups joined by other sockets on the
host. This can give SDK initialization a packet from a different LiDAR model.

For multicast, `SocketSource` now binds the group destination on POSIX platforms
and disables `IP_MULTICAST_ALL` where available. `localIp` still selects the
interface used for group membership. Unicast binding is unchanged. Invalid
multicast addresses and failed membership/isolation setup fail `Open()` and
close the socket instead of reporting a usable receiver.

Windows retains its existing interface binding; Windows behavior was not tested.

## Regression test

```sh
cmake -S . -B build-socket-tests -DDISENABLE_TEST_CC=ON -DWITH_PTCS_USE=OFF -DFIND_CUDA=OFF -DBUILD_SOCKET_TESTS=ON
cmake --build build-socket-tests -j2
ctest --test-dir build-socket-tests --output-on-failure
```

The test uses ephemeral UDP ports and multicast TTL zero (local delivery only).
It checks two distinct groups sharing one port, both default and explicitly
selected loopback interfaces, unicast exclusion from multicast sockets, existing
unicast reception, invalid group rejection and failed membership cleanup.
The default-interface case requires an available multicast-capable route.

On upstream `357ff14`, both receivers returned `AB` after sending `A` and `B`
to separate groups. With this fix, they return only `A` and `B`, respectively.
Linux x86_64 CTest passed five consecutive repetitions. The parent ROS 2 Jazzy
driver also built successfully with its multicast/E1R tests passing.
Physical MPBV sensor validation was interrupted by loss of remote connectivity.
