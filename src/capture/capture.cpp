#include "capture.h"
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace maple {

// Build a map from adapter GUID to friendly name using Windows API
static std::unordered_map<std::string, std::string> getAdapterFriendlyNames() {
    std::unordered_map<std::string, std::string> result;
#ifdef _WIN32
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    ULONG ret = 0;

    // Retry loop as recommended by MSDN
    for (int i = 0; i < 3; i++) {
        addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(malloc(bufLen));
        if (!addrs) return result;
        ret = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &bufLen);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            free(addrs);
            addrs = nullptr;
            continue;
        }
        break;
    }

    if (ret != NO_ERROR || !addrs) {
        free(addrs);
        return result;
    }

    for (auto a = addrs; a; a = a->Next) {
        // AdapterName is the GUID string (without braces on some versions, with on others)
        std::string guid = a->AdapterName;

        // Convert FriendlyName (wide) to UTF-8
        int needed = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 0) {
            std::string friendly(needed - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, friendly.data(), needed, nullptr, nullptr);
            result[guid] = friendly;
        }
    }

    free(addrs);
#endif
    return result;
}

// Extract GUID from NPF device name like "\\Device\\NPF_{GUID}"
static std::string extractGuid(const std::string& npfName) {
    auto pos = npfName.find('{');
    if (pos == std::string::npos) return "";
    auto end = npfName.find('}', pos);
    if (end == std::string::npos) return "";
    return npfName.substr(pos, end - pos + 1);
}

Capture::Capture() = default;

Capture::~Capture() {
    stop();
}

std::vector<NetworkInterface> Capture::listInterfaces() {
    std::vector<NetworkInterface> result;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[Capture] Error finding devices: " << errbuf << std::endl;
        return result;
    }

    auto friendlyNames = getAdapterFriendlyNames();

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        NetworkInterface iface;
        iface.name = d->name;

        // Try to find friendly name by matching GUID
        std::string guid = extractGuid(d->name);
        auto it = friendlyNames.find(guid);
        if (it != friendlyNames.end()) {
            iface.friendlyName = it->second;
        }

        iface.description = d->description ? d->description : "";
        result.push_back(std::move(iface));
    }

    pcap_freealldevs(alldevs);
    return result;
}

bool Capture::start(const std::string& interfaceName, const std::string& bpfFilter) {
    if (running_) {
        std::cerr << "[Capture] Already running." << std::endl;
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(
        interfaceName.c_str(),
        65535,  // snaplen
        1,      // promisc
        1,      // timeout ms (low latency)
        errbuf
    );

    if (!handle_) {
        std::cerr << "[Capture] Error opening device: " << errbuf << std::endl;
        return false;
    }

    // Increase kernel buffer to 128MB to avoid drops during bursts
    if (pcap_setbuff(handle_, 128 * 1024 * 1024) != 0) {
        std::cerr << "[Capture] Warning: failed to set buffer size" << std::endl;
    }

    if (!bpfFilter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, bpfFilter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "[Capture] Error compiling filter: " << pcap_geterr(handle_) << std::endl;
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "[Capture] Error setting filter: " << pcap_geterr(handle_) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        pcap_freecode(&fp);
    }

    currentInterface_ = interfaceName;
    currentFilter_ = bpfFilter;
    running_ = true;
    captureThread_ = std::thread(&Capture::captureLoop, this);

    std::cout << "[Capture] Started on " << interfaceName << std::endl;
    return true;
}

void Capture::stop() {
    if (!running_) return;

    running_ = false;

    if (handle_) {
        pcap_breakloop(handle_);
    }

    if (captureThread_.joinable()) {
        captureThread_.join();
    }

    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }

    currentInterface_.clear();
    currentFilter_.clear();
    std::cout << "[Capture] Stopped." << std::endl;
}

bool Capture::isRunning() const {
    return running_;
}

void Capture::setPacketCallback(PacketCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(cb);
}

void Capture::pcapCallback(u_char* user, const pcap_pkthdr* header, const u_char* packet) {
    auto* self = reinterpret_cast<Capture*>(user);

    RawPacket pkt;
    pkt.len = header->len;
    pkt.caplen = header->caplen;
    pkt.timestamp = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
    pkt.data.assign(packet, packet + header->caplen);

    // Copy callback under lock, invoke outside to avoid blocking capture thread
    PacketCallback cb;
    {
        std::lock_guard<std::mutex> lock(self->mutex_);
        cb = self->callback_;
    }
    if (cb) {
        cb(pkt);
    }
}

void Capture::captureLoop() {
    pcap_loop(handle_, 0, pcapCallback, reinterpret_cast<u_char*>(this));
}

} // namespace maple
