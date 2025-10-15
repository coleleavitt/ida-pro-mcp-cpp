#pragma once

#include <memory>
#include <thread>
#include <atomic>

namespace httplib {
    class Server;
}

class McpServer {
public:
    static McpServer &instance();

    void start();

    void stop();

    bool is_running() const;

private:
    McpServer() = default;

    std::unique_ptr<std::thread> server_thread_;
    std::atomic<bool> running_{false};
    std::unique_ptr<httplib::Server> http_server_;

    void server_thread_func();
};
