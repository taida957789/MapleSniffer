#include "capture/capture.h"
#include "protocol/protocol.h"
#include "app/app.h"
#ifdef _WIN32
#include <windows.h>
#endif

coco::stray start(saucer::application *app) {
    maple::Capture capture;
    maple::Protocol protocol;
    maple::App mApp(capture);

    capture.setPacketCallback([&protocol, &mApp](const maple::RawPacket& raw) {
        try {
            auto packets = protocol.process(raw);
            if (!packets.empty()) {
                mApp.addPackets(packets);
            }
        } catch (...) {}
    });

    mApp.setup(app);

    co_await app->finish();
    capture.stop();
}

int main() {
    return saucer::application::create({.id = "maple-sniffer"})->run(start);
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    return main();
}
#endif
