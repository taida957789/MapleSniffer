#pragma once

#include <pcap.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace maple {

struct RawPacket {
    std::vector<uint8_t> data;
    uint32_t len;
    uint32_t caplen;
    double timestamp;
};

struct NetworkInterface {
    std::string name;        // NPF device name (used for pcap_open)
    std::string friendlyName; // Windows friendly name, e.g. "乙太網路", "Wi-Fi"
    std::string description;  // pcap description
};

class Capture {
public:
    using PacketCallback = std::function<void(const RawPacket&)>;

    Capture();
    ~Capture();

    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    std::vector<NetworkInterface> listInterfaces();
    bool start(const std::string& interfaceName, const std::string& bpfFilter = "");
    void stop();
    bool isRunning() const;

    const std::string& currentInterface() const { return currentInterface_; }
    const std::string& currentFilter() const { return currentFilter_; }

    void setPacketCallback(PacketCallback cb);

private:
    static void pcapCallback(u_char* user, const pcap_pkthdr* header, const u_char* packet);
    void captureLoop();

    pcap_t* handle_ = nullptr;
    std::thread captureThread_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;
    PacketCallback callback_;
    std::string currentInterface_;
    std::string currentFilter_;
};

} // namespace maple
