#pragma once

#include "../capture/capture.h"
#include "../protocol/protocol.h"
#include "httplib.h"
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>

namespace maple {

class Server {
public:
    Server(Capture& capture, int port = 8080);
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    void start();
    void stop();

    // Called by capture callback to record packets
    void addPacket(const Packet& pkt);
    void addPackets(const std::vector<Packet>& pkts);

private:
    void setupRoutes();
    void serveStaticFiles();

    Capture& capture_;
    httplib::Server svr_;
    std::thread serverThread_;
    int port_;

    std::deque<Packet> packets_;
    std::mutex packetsMutex_;
    static constexpr size_t MAX_PACKETS = 500;
};

} // namespace maple
