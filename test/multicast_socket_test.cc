#include <socket_source.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
void require(bool ok, const char *message)
{
  if (!ok) throw std::runtime_error(message);
}

uint16_t unusedPort()
{
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  require(fd >= 0, "port probe socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  require(bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "port probe bind");
  socklen_t size = sizeof(address);
  require(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size) == 0, "port probe name");
  close(fd);
  return ntohs(address.sin_port);
}

void sendMarker(int fd, const char *group, uint16_t port, uint8_t marker)
{
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  require(inet_pton(AF_INET, group, &address.sin_addr) == 1, "destination address");
  require(sendto(fd, &marker, 1, 0, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 1,
          "send marker");
}

std::vector<uint8_t> collect(hesai::lidar::SocketSource &source)
{
  std::vector<uint8_t> result;
  const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
  while (std::chrono::steady_clock::now() < until) {
    hesai::lidar::UdpPacket packet;
    if (source.Receive(packet, sizeof(packet.buffer)) > 0) result.push_back(packet.buffer[0]);
  }
  return result;
}

void multicastCase(const std::string &interface)
{
  const auto port = unusedPort();
  hesai::lidar::SocketSource a(port, interface, "239.255.87.141");
  hesai::lidar::SocketSource b(port, interface, "239.255.87.143");
  require(a.Open() && b.Open(), "open multicast sources");
  const int sender = socket(AF_INET, SOCK_DGRAM, 0);
  require(sender >= 0, "sender socket");
  const unsigned char ttl = 0, loop = 1;
  require(setsockopt(sender, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == 0, "local-only TTL");
  require(setsockopt(sender, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) == 0, "loopback");
  if (!interface.empty()) {
    in_addr local{};
    require(inet_pton(AF_INET, interface.c_str(), &local) == 1, "interface address");
    require(setsockopt(sender, IPPROTO_IP, IP_MULTICAST_IF, &local, sizeof(local)) == 0, "sender interface");
  }
  sendMarker(sender, "239.255.87.141", port, 'A');
  sendMarker(sender, "239.255.87.143", port, 'B');
  sendMarker(sender, "127.0.0.1", port, 'U');
  close(sender);
  const auto first = collect(a), second = collect(b);
  std::cout << "interface=" << interface << " group A received="
            << std::string(first.begin(), first.end()) << " group B received="
            << std::string(second.begin(), second.end()) << std::endl;
  require(first == std::vector<uint8_t>{'A'} && second == std::vector<uint8_t>{'B'},
          "multicast sockets must isolate groups sharing a UDP port");
}
}  // namespace

int main()
{
  try {
    multicastCase("");
    multicastCase("127.0.0.1");
    const auto port = unusedPort();
    hesai::lidar::SocketSource unicast(port, "127.0.0.1", "");
    require(unicast.Open(), "open unicast source");
    const int sender = socket(AF_INET, SOCK_DGRAM, 0);
    require(sender >= 0, "unicast sender");
    sendMarker(sender, "127.0.0.1", port, 'U');
    close(sender);
    require(collect(unicast) == std::vector<uint8_t>{'U'}, "unicast regression");
    for (const char *invalid : {"not-an-ip", "127.0.0.1", "255.255.255.255"}) {
      hesai::lidar::SocketSource bad(unusedPort(), "", invalid);
      require(!bad.Open() && !bad.IsOpened(), "invalid group must fail closed");
    }
    hesai::lidar::SocketSource bad_interface(unusedPort(), "192.0.2.254", "239.255.87.141");
    require(!bad_interface.Open() && !bad_interface.IsOpened(), "failed membership must fail closed");
  } catch (const std::exception &error) {
    std::cerr << error.what() << std::endl;
    return 1;
  }
  return 0;
}
