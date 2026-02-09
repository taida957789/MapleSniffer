#include "server.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <unordered_map>

// Include embedded web resources if available
#if __has_include("web_resources.h")
#include "web_resources.h"
#define HAS_WEB_RESOURCES 1
#else
#define HAS_WEB_RESOURCES 0
#endif

using json = nlohmann::json;

namespace maple {

Server::Server(Capture& capture, int port)
    : capture_(capture), port_(port) {}

Server::~Server() {
    stop();
}

void Server::start() {
    setupRoutes();
    serveStaticFiles();

    serverThread_ = std::thread([this]() {
        std::cout << "[Server] Listening on http://localhost:" << port_ << std::endl;
        svr_.listen("0.0.0.0", port_);
    });
}

void Server::stop() {
    svr_.stop();
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
}

void Server::addPacket(const Packet& pkt) {
    std::lock_guard<std::mutex> lock(packetsMutex_);
    packets_.push_back(pkt);
    if (packets_.size() > MAX_PACKETS) {
        packets_.pop_front();
    }
}

static std::string getMimeType(const std::string& path) {
    if (path.ends_with(".html")) return "text/html";
    if (path.ends_with(".js"))   return "application/javascript";
    if (path.ends_with(".css"))  return "text/css";
    if (path.ends_with(".svg"))  return "image/svg+xml";
    if (path.ends_with(".png"))  return "image/png";
    if (path.ends_with(".ico"))  return "image/x-icon";
    if (path.ends_with(".json")) return "application/json";
    if (path.ends_with(".woff")) return "font/woff";
    if (path.ends_with(".woff2")) return "font/woff2";
    return "application/octet-stream";
}

void Server::setupRoutes() {
    // GET /api/status
    svr_.Get("/api/status", [this](const httplib::Request&, httplib::Response& res) {
        json j;
        j["capturing"] = capture_.isRunning();
        {
            std::lock_guard<std::mutex> lock(packetsMutex_);
            j["packetCount"] = packets_.size();
        }
        res.set_content(j.dump(), "application/json");
    });

    // GET /api/interfaces
    svr_.Get("/api/interfaces", [this](const httplib::Request&, httplib::Response& res) {
        auto ifaces = capture_.listInterfaces();
        json j = json::array();
        for (const auto& iface : ifaces) {
            j.push_back({
                {"name", iface.name},
                {"friendlyName", iface.friendlyName},
                {"description", iface.description}
            });
        }
        res.set_content(j.dump(), "application/json");
    });

    // POST /api/capture/start
    svr_.Post("/api/capture/start", [this](const httplib::Request& req, httplib::Response& res) {
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            res.set_content(R"({"error":"invalid JSON"})", "application/json");
            return;
        }

        std::string ifaceName = body.value("interface", "");
        std::string filter = body.value("filter", "");

        if (ifaceName.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"interface is required"})", "application/json");
            return;
        }

        if (capture_.isRunning()) {
            capture_.stop();
        }

        // Clear old packets
        {
            std::lock_guard<std::mutex> lock(packetsMutex_);
            packets_.clear();
        }

        bool ok = capture_.start(ifaceName, filter);
        json j;
        j["success"] = ok;
        res.set_content(j.dump(), "application/json");
    });

    // POST /api/capture/stop
    svr_.Post("/api/capture/stop", [this](const httplib::Request&, httplib::Response& res) {
        capture_.stop();
        json j;
        j["success"] = true;
        res.set_content(j.dump(), "application/json");
    });

    // GET /api/packets
    svr_.Get("/api/packets", [this](const httplib::Request& req, httplib::Response& res) {
        int since = 0;
        if (req.has_param("since")) {
            try {
                since = std::stoi(req.get_param_value("since"));
            } catch (...) {}
        }

        std::lock_guard<std::mutex> lock(packetsMutex_);
        json j = json::array();
        int idx = 0;
        for (const auto& pkt : packets_) {
            if (idx >= since) {
                j.push_back({
                    {"index", idx},
                    {"timestamp", pkt.timestamp},
                    {"length", pkt.length},
                    {"hexDump", pkt.hexDump},
                    {"inbound", pkt.inbound}
                });
            }
            idx++;
        }
        res.set_content(j.dump(), "application/json");
    });
}

void Server::serveStaticFiles() {
#if HAS_WEB_RESOURCES
    svr_.Get("/(.*)", [](const httplib::Request& req, httplib::Response& res) {
        std::string path = "/" + std::string(req.matches[1]);
        if (path == "/") path = "/index.html";

        auto it = web_resources.find(path);
        if (it != web_resources.end()) {
            res.set_content(
                reinterpret_cast<const char*>(it->second.first),
                it->second.second,
                getMimeType(path)
            );
        } else {
            // SPA fallback: serve index.html for non-API, non-asset routes
            auto idx = web_resources.find("/index.html");
            if (idx != web_resources.end()) {
                res.set_content(
                    reinterpret_cast<const char*>(idx->second.first),
                    idx->second.second,
                    "text/html"
                );
            } else {
                res.status = 404;
                res.set_content("Not Found", "text/plain");
            }
        }
    });
#else
    // No embedded resources: serve a placeholder
    svr_.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(
            "<html><body><h1>MapleAuto</h1>"
            "<p>Frontend not embedded. Build frontend first, then rebuild C++ project.</p>"
            "</body></html>",
            "text/html"
        );
    });
#endif
}

} // namespace maple
