/************************************************************************************************
Copyright (C) 2023 Hesai Technology Co., Ltd.
Copyright (C) 2023 Original Authors
All rights reserved.

All code in this repository is released under the terms of the following Modified BSD License. 
Redistribution and use in source and binary forms, with or without modification, are permitted 
provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and 
  the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and 
  the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its contributors may be used to endorse or 
  promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
************************************************************************************************/
#include "pcap_source.h"

#include <stdexcept>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

using namespace hesai::lidar;

static constexpr uint32_t pcap_magic_number = 0xa1b2c3d4;

PcapIPHeader::PcapIPHeader(uint8_t protocol, uint16_t pkt_len)
    : ether{ {0xff,0xff,0xff,0xff,0xff,0xff}, {0x00, 0x0a, 0x35, 0x00, 0x1e, 0x53}, 0x0008 }
    , ip{ 0x5, 0x4, 0x00, uint16_t((((pkt_len + 20) & 0xff) << 8) | ((pkt_len + 20) >> 8)), 0xf17a, 0x0040, 0x40, protocol, 0x80f8, 0xc901a8c0, 0xffffffff }
{}

PcapIPv6Header::PcapIPv6Header(uint8_t protocol, uint16_t pkt_len)
    : ether{ {0xff,0xff,0xff,0xff,0xff,0xff}, {0x00, 0x0a, 0x35, 0x00, 0x1e, 0x53}, 0xdd86 }
    , ipv6 { 0x6, 0, 0, 0, uint8_t((((pkt_len + 40) & 0xff) << 8) | ((pkt_len + 40) >> 8)), protocol, }
{}

PcapUDPHeader::PcapUDPHeader(uint16_t pkt_len, uint16_t port)
    : PcapIPHeader::PcapIPHeader(0x11, pkt_len + 8)
    , udp{ 0x1027, uint16_t(((port & 0xff) << 8) | (port >> 8)), uint16_t((((pkt_len + 8) & 0xff) << 8) | ((pkt_len + 8) >> 8)), 0x0000 }
{}

PcapUDPv6Header::PcapUDPv6Header(uint16_t pkt_len, uint16_t port)
    : PcapIPv6Header::PcapIPv6Header(0x11, pkt_len + 8)
    , udp{ 0x1027, uint16_t(((port & 0xff) << 8) | (port >> 8)), uint16_t((((pkt_len + 8) & 0xff) << 8) | ((pkt_len + 8) >> 8)), 0x0000 }
{}

PcapTCPHeader::PcapTCPHeader(uint16_t pkt_len, uint16_t port)
    : PcapIPHeader::PcapIPHeader(0x06, pkt_len + 20)
    , tcp{ 0x1027, uint16_t(((port & 0xff) << 8) | (port >> 8)), 0x000000000, 0x00000000, 0x4, 0x0, 0x0, 0x00, 0x0000, 0x0000, 0x0000 }
{}

PcapTCPv6Header::PcapTCPv6Header(uint16_t pkt_len, uint16_t port)
    : PcapIPv6Header::PcapIPv6Header(0x06, pkt_len + 20)
    , tcp{ 0x1027, uint16_t(((port & 0xff) << 8) | (port >> 8)), 0x000000000, 0x00000000, 0x4, 0x0, 0x0, 0x00, 0x0000, 0x0000, 0x0000 }
{}

class PcapSource::Private {
    std::ifstream _fpcap;
    size_t _fpos;
    std::vector<char> _fileData;

public:
    Private() : _fpos(0) {}
    ~Private() { close(); }

    void open(const std::string& pcap_path) {
        close();
        _fpcap.open(pcap_path, std::ios::binary);
        if (_fpcap.is_open()) {
            _fpcap.seekg(0, std::ios::end);
            _fileData.resize(_fpcap.tellg());
            _fpcap.seekg(0, std::ios::beg);
            _fpcap.read(&_fileData[0], _fileData.size());
        }
    }

    bool is_open() const { return _fpcap.is_open(); }

    void close() {
        if (is_open()) {
            _fpcap.close();
            _fileData.clear();
        }
        _fpos = 0;
    }

    inline bool eof() const { return _fpos == _fileData.size(); }

    inline size_t fpos() const { return _fpos; }

    inline void fpos(size_t new_fpos) { _fpos = new_fpos; }

    template<typename T>
    bool read(T& value) {
        if (_fpos + sizeof(T) > _fileData.size()) return false;
        //std::memcpy(&value, &_fileData[_fpos], sizeof(T));
        value = *(T*)(&_fileData[_fpos]);
        _fpos += sizeof(T);
        return true;
    }

    bool read(void* dst, size_t length) {
        if (_fpos + length > _fileData.size()) return false;
        std::memcpy(dst, &_fileData[_fpos], length);
        _fpos += length;
        return true;
    }

    bool move(size_t length) {
        if (_fpos + length > _fileData.size()) return false;
        _fpos += length;
        return true;
    }
};

PcapSource::PcapSource(std::string path, int packet_interval)
    : _p(new Private)
    , pcap_udp_header_{0, 0, 0, 0}
    , is_live_mode_(false)
#ifdef __linux__
    , pcap_handle_(nullptr)
#endif
{
    pcap_path_ = path;
    packet_interval_ = packet_interval;
    mac_filter_ = "";  // Default: no MAC filtering
}

PcapSource::~PcapSource() {
    PcapSource::Close();
    delete _p;
}

PcapSource::Callback PcapSource::callback() const {
    return udp_callback_;
}

void PcapSource::callback(Callback callback) {
    udp_callback_ = callback;
}
PcapSource::Callback PcapSource::tcp_callback() const {
    return tcp_callback_;
}

void PcapSource::tcp_callback(Callback callback) {
    tcp_callback_ = callback;
}

size_t PcapSource::fpos() const
{
    return _p->fpos();
}

void PcapSource::fpos(size_t new_fpos)
{
    _p->fpos(new_fpos);
}

void PcapSource::setMacFilter(const std::string& mac_address) {
    mac_filter_ = mac_address;
}

void PcapSource::setLiveMode(bool live_mode) {
    is_live_mode_ = live_mode;
}

std::string PcapSource::macFilter() const {
    return mac_filter_;
}

bool PcapSource::isLiveMode() const {
    return is_live_mode_;
}

bool PcapSource::Open() {
    try
    {
        PcapSource::Close();
        
        if (is_live_mode_) {
#ifdef __linux__
            // Live capture mode using libpcap
            char errbuf[PCAP_ERRBUF_SIZE];
            
            // Open live capture on specified interface
            pcap_handle_ = pcap_open_live(pcap_path_.c_str(), 65536, 1, 1000, errbuf);
            if (pcap_handle_ == nullptr) {
                throw std::runtime_error(std::string("Failed to open live capture on interface: ") + pcap_path_ + " - " + errbuf);
            }
            
            // Set up MAC address filter if specified
            if (!mac_filter_.empty()) {
                std::string filter_str = "ether src " + mac_filter_;
                if (pcap_compile(pcap_handle_, &filter_program_, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
                    LogError("Failed to compile MAC filter: %s", pcap_geterr(pcap_handle_));
                } else {
                    if (pcap_setfilter(pcap_handle_, &filter_program_) == -1) {
                        LogError("Failed to set MAC filter: %s", pcap_geterr(pcap_handle_));
                    }
                }
            }
            
            LogInfo("Opened live capture on interface: %s", pcap_path_.c_str());
            return true;
#else
            throw std::runtime_error("Live capture mode is only supported on Linux");
#endif
        } else {
            // File-based pcap mode
            _p->open(pcap_path_);
            if (!_p->is_open()) {
                throw std::runtime_error(std::string("Fail to open .pcap file: \"") + (pcap_path_)+"\"");
            }
            _p->read(pcap_header_);
            if (pcap_header_.magic_number != pcap_magic_number) {
                throw std::runtime_error(std::string("Not a valid .pcap file: \"") + (pcap_path_)+"\"");
            }
            return true;
        }
    }
    catch (const std::exception& e)
    {
        LogError("%s", e.what());
        return false;
    }
}

std::string PcapSource::pcap_path() const {
    return pcap_path_;
}

int PcapSource::next(UdpPacket& udpPacket, uint16_t u16Len, int flags,
                      int timeout) {
    if (is_live_mode_) {
#ifdef __linux__
        return nextLivePacket(udpPacket, u16Len, flags, timeout);
#else
        return -1;  // Live mode not supported on non-Linux systems
#endif
    }
    
    if(_p->eof()) {
        is_pcap_end = true;
        return -1;
    }
    bool ret = _p->read(pcap_record_);
    if (!ret) return -1;
    if (pcap_record_.incl_len <= 1500 && pcap_record_.incl_len > sizeof(Ethernet)) {
        ret = _p->read(payload_.data(), pcap_record_.incl_len);
        if (!ret) return -1;
        switch (((Ethernet*)payload_.data())->ether_type)
        {
        case 0x0008: // ipv4
            switch (((PcapIPHeader*)payload_.data())->ip.protocol)
            {
            case 17:
                pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPHeader));
                if (pcap_record_.incl_len < sizeof(PcapUDPHeader)) return 1;
                memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPHeader), pcap_record_.incl_len - sizeof(PcapUDPHeader));
                return pcap_record_.incl_len - sizeof(PcapUDPHeader);
                break;
            case 6:
                if (pcap_record_.incl_len < sizeof(PcapTCPHeader)) return 1;
                pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPHeader));
                if (tcp_callback_)
                    return pcap_record_.incl_len - sizeof(PcapTCPHeader);
                else
                    return 2;
                break;
            default:
                return 2;
                break;
            }
            break;
        case 0xdd86: // ipv6 
            switch (((PcapIPv6Header*)payload_.data())->ipv6.next_header)
            {
            case 17:
                pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPv6Header));
                if (pcap_record_.incl_len < sizeof(PcapUDPv6Header)) return 1;
                memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPv6Header), pcap_record_.incl_len - sizeof(PcapUDPv6Header));
                return pcap_record_.incl_len - sizeof(PcapUDPv6Header);
                break;
            case 6:
                if (pcap_record_.incl_len < sizeof(PcapTCPv6Header)) return 1;
                pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPv6Header));
                if (tcp_callback_)
                    return pcap_record_.incl_len - sizeof(PcapTCPv6Header);
                else
                    return 2;
                break;
            default:
                return 2;
                break;
            }
            break;
        case 0x0081:  // vlan tag
        switch (*((uint16_t*)(payload_.data() + sizeof(Ethernet) + 2)))
            {
            case 0x0008:
                switch (*((uint8_t*)(payload_.data() + sizeof(Ethernet) + 13)))
                {
                case 17:
                    pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPHeader));
                    if (pcap_record_.incl_len < sizeof(PcapUDPHeader) + 4) return 1;
                    memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPHeader) + 4, pcap_record_.incl_len - sizeof(PcapUDPHeader) - 4);
                    return pcap_record_.incl_len - sizeof(PcapUDPHeader) - 4;
                    break;
                case 6:
                    if (pcap_record_.incl_len < sizeof(PcapTCPHeader) + 4) return 1;
                    pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPHeader));
                    if (tcp_callback_)
                        return pcap_record_.incl_len - sizeof(PcapTCPHeader) - 4;
                    else
                        return 2;
                    break;
                default:
                    return 2;
                    break;
                }
                break;
            case 0xdd86:
                switch (*((uint8_t*)(payload_.data() + sizeof(Ethernet) + 13)))
                {
                case 17:
                    if (pcap_record_.incl_len < sizeof(PcapUDPv6Header) + 4) return 1;
                    pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPv6Header));
                    return pcap_record_.incl_len - sizeof(PcapUDPv6Header) - 4;
                    break;
                case 6:
                    if (pcap_record_.incl_len < sizeof(PcapTCPv6Header) + 4) return 1;
                    pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPv6Header));
                    if (tcp_callback_)
                        return pcap_record_.incl_len - sizeof(PcapTCPv6Header) - 4;
                    else
                        return 2;
                    break;
                default:
                    return 2;
                    break;
                }
            default:
                return 2;
                break;
            }
            break;
        default:
        LogWarning("can not parser Ethernet data, type = %x ", ((Ethernet*)payload_.data())->ether_type);
            break;
        }
    }
    else {
        ret = _p->move(pcap_record_.incl_len);
        if (!ret) return -1;
        return 1;
    }
    return 1;
}
int PcapSource::distinationPort() {
    uint16_t port = pcap_udp_header_.distination_port;
    return ((port & 0xff) << 8) | ((port >> 8) & 0xff);
}

void PcapSource::Close() {
    if (is_live_mode_) {
#ifdef __linux__
        if (pcap_handle_) {
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
#endif
    } else {
        _p->close();
    }
}


bool PcapSource::IsOpened() {
    if (is_live_mode_) {
#ifdef __linux__
        return pcap_handle_ != nullptr;
#else
        return false;
#endif
    } else {
        return _p->is_open();
    }
}

int PcapSource::Receive(UdpPacket& udpPacket, uint16_t u16Len, int flags,
                       int iTimeout) {
  return next(udpPacket, u16Len, flags, iTimeout);
}

int PcapSource::Send(uint8_t* u8Buf, uint16_t u16Len, int flags) {
  return u16Len;
}

void PcapSource::setPcapPath(std::string path) {
    pcap_path_ = path;
}

void PcapSource::setPacketInterval(int microsecond) {
    packet_interval_ = microsecond;
}

bool PcapSource::checkMacFilter(const uint8_t* ethernet_header) {
    // If no MAC filter is set, accept all packets
    if (mac_filter_.empty()) {
        return true;
    }
    
    // Extract source MAC address from Ethernet header
    const Ethernet* eth = reinterpret_cast<const Ethernet*>(ethernet_header);
    
    // Convert MAC filter string to bytes for comparison
    std::stringstream ss(mac_filter_);
    std::string byte_str;
    uint8_t filter_mac[6];
    int i = 0;
    
    while (std::getline(ss, byte_str, ':') && i < 6) {
        filter_mac[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        i++;
    }
    
    // Compare source MAC address
    return (memcmp(eth->source_MAC_address, filter_mac, 6) == 0);
}

#ifdef __linux__
int PcapSource::nextLivePacket(UdpPacket& udpPacket, uint16_t u16Len, int flags, int timeout) {
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    
    int result = pcap_next_ex(pcap_handle_, &header, &packet_data);
    
    if (result == 1) {
        // Packet captured successfully
        if (header->caplen <= 1500 && header->caplen > sizeof(Ethernet)) {
            // Apply MAC address filter if specified
            if (!checkMacFilter(packet_data)) {
                return 1;  // Skip this packet, try next one
            }
            
            // Copy packet data to payload
            memcpy(payload_.data(), packet_data, header->caplen);
            
            // Initialize UdpPacket fields for compatibility with SocketSource
            udpPacket.packet_len = 0;
            udpPacket.is_timeout = false;
            udpPacket.recv_timestamp = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
            udpPacket.ip = 0;
            udpPacket.port = 0;
            
            switch (((Ethernet*)payload_.data())->ether_type) {
            case 0x0008: // IPv4
                {
                    const PcapIPHeader* ip_hdr = (const PcapIPHeader*)payload_.data();
                    // Extract source IP address for compatibility
                    udpPacket.ip = ip_hdr->ip.srce_addr;
                    
                    switch (ip_hdr->ip.protocol) {
                    case 17: // UDP
                        {
                            pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPHeader));
                            if (header->caplen < sizeof(PcapUDPHeader)) return 1;
                            
                            // Set source port for compatibility
                            udpPacket.port = pcap_udp_header_.source_port;
                            
                            int payload_size = header->caplen - sizeof(PcapUDPHeader);
                            memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPHeader), payload_size);
                            udpPacket.packet_len = payload_size;
                            return payload_size;
                        }
                    case 6: // TCP
                    if (header->caplen < sizeof(PcapTCPHeader)) return 1;
                    pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPHeader));
                    if (tcp_callback_)
                        return header->caplen - sizeof(PcapTCPHeader);
                    else
                        return 2;
                    default:
                        return 2;
                    }
                }
                break;
                
            case 0xdd86: // IPv6
                {
                    const PcapIPv6Header* ipv6_hdr = (const PcapIPv6Header*)payload_.data();
                    // For IPv6, we can't easily fit into 32-bit ip field, so leave as 0
                    
                    switch (ipv6_hdr->ipv6.next_header) {
                    case 17: // UDP
                        {
                            pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPv6Header));
                            if (header->caplen < sizeof(PcapUDPv6Header)) return 1;
                            
                            // Set source port for compatibility
                            udpPacket.port = pcap_udp_header_.source_port;
                            
                            int payload_size = header->caplen - sizeof(PcapUDPv6Header);
                            memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPv6Header), payload_size);
                            udpPacket.packet_len = payload_size;
                            return payload_size;
                        }
                    case 6: // TCP
                    if (header->caplen < sizeof(PcapTCPv6Header)) return 1;
                    pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPv6Header));
                    if (tcp_callback_)
                        return header->caplen - sizeof(PcapTCPv6Header);
                    else
                        return 2;
                    default:
                        return 2;
                    }
                }
                break;
                
            case 0x0081: // VLAN tag
                switch (*((uint16_t*)(payload_.data() + sizeof(Ethernet) + 2))) {
                case 0x0008: // IPv4
                    switch (*((uint8_t*)(payload_.data() + sizeof(Ethernet) + 13))) {
                    case 17: // UDP
                        {
                            pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPHeader));
                            if (header->caplen < sizeof(PcapUDPHeader) + 4) return 1;
                            
                            // Set source port for compatibility
                            udpPacket.port = pcap_udp_header_.source_port;
                            
                            int payload_size = header->caplen - sizeof(PcapUDPHeader) - 4;
                            memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPHeader) + 4, payload_size);
                            udpPacket.packet_len = payload_size;
                            return payload_size;
                        }
                    case 6: // TCP
                        if (header->caplen < sizeof(PcapTCPHeader) + 4) return 1;
                        pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPHeader));
                        if (tcp_callback_)
                            return header->caplen - sizeof(PcapTCPHeader) - 4;
                        else
                            return 2;
                    default:
                        return 2;
                    }
                    break;
                case 0xdd86: // IPv6
                    switch (*((uint8_t*)(payload_.data() + sizeof(Ethernet) + 13))) {
                    case 17: // UDP
                        {
                            if (header->caplen < sizeof(PcapUDPv6Header) + 4) return 1;
                            pcap_udp_header_ = *(const UDP*)(payload_.data() + sizeof(PcapIPv6Header));
                            
                            // Set source port for compatibility
                            udpPacket.port = pcap_udp_header_.source_port;
                            
                            int payload_size = header->caplen - sizeof(PcapUDPv6Header) - 4;
                            memcpy(udpPacket.buffer, payload_.data() + sizeof(PcapUDPv6Header) + 4, payload_size);
                            udpPacket.packet_len = payload_size;
                            return payload_size;
                        }
                    case 6: // TCP
                        if (header->caplen < sizeof(PcapTCPv6Header) + 4) return 1;
                        pcap_tcp_header_ = *(const TCP*)(payload_.data() + sizeof(PcapIPv6Header));
                        if (tcp_callback_)
                            return header->caplen - sizeof(PcapTCPv6Header) - 4;
                        else
                            return 2;
                    default:
                        return 2;
                    }
                default:
                    return 2;
                }
                break;
                
            default:
                LogWarning("Cannot parse Ethernet data, type = %x", ((Ethernet*)payload_.data())->ether_type);
                break;
            }
        }
        return 1;
    } else if (result == 0) {
        // Timeout
        udpPacket.is_timeout = true;
        return 0;  // Return 0 for timeout like SocketSource
    } else if (result == -1) {
        // Error
        LogError("Error reading packet: %s", pcap_geterr(pcap_handle_));
        return -1;
    } else if (result == -2) {
        // End of file (shouldn't happen in live mode)
        return -1;
    }
    
    return 1;
}
#endif