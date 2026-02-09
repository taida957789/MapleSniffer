#include "capture/capture.h"
#include "protocol/protocol.h"
#include "server/server.h"
#include <iostream>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running{true};

void signalHandler(int) {
    g_running = false;
}

int main() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::cout << "=== MapleAuto ===" << std::endl;

    maple::Capture capture;
    maple::Protocol protocol;
    maple::Server server(capture, 8080);

    // Wire capture -> protocol -> server
    capture.setPacketCallback([&protocol, &server](const maple::RawPacket& raw) {
        auto packets = protocol.process(raw);
        if (!packets.empty()) {
            server.addPackets(packets);
        }
    });

    server.start();

    std::cout << "Press Ctrl+C to stop..." << std::endl;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\nShutting down..." << std::endl;
    capture.stop();
    server.stop();

    return 0;
}
