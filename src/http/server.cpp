#include "http/server.hpp"
#include "http/auth.hpp"
#include "http/handlers.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>

#define DONT_DEFINE_HEXRAYS 1
#include <ida.hpp>

#ifdef snprintf
#undef snprintf
#endif
#ifdef fgetc
#undef fgetc
#endif
#ifdef wait
#undef wait
#endif

#include <kernwin.hpp>

McpServer& McpServer::instance() {
    static McpServer server;
    return server;
}

void McpServer::start() {
    if (running_) {
        msg("[IDA MCP] Server already running on port 3000\n");
        msg("[IDA MCP] Bearer Token: %s\n", SESSION_TOKEN.c_str());
        return;
    }
    
    running_ = true;
    server_thread_ = std::make_unique<std::thread>(&McpServer::server_thread_func, this);
    
    msg("\n=== IDA MCP Server Started ===\n");
    msg("URL: http://127.0.0.1:3000/mcp\n");
    msg("Token: %s\n", SESSION_TOKEN.c_str());
    msg("\nClaude Code command:\n");
    msg("  claude mcp add -t http -s user ida-pro http://127.0.0.1:3000/mcp \\\n");
    msg("    -H \"Authorization: Bearer %s\"\n", SESSION_TOKEN.c_str());
    msg("===============================\n\n");
}

void McpServer::stop() {
    if (running_ && http_server_) {
        http_server_->stop();
        if (server_thread_ && server_thread_->joinable()) {
            server_thread_->join();
        }
        running_ = false;
        msg("[IDA MCP] Server stopped\n");
    }
}

bool McpServer::is_running() const {
    return running_;
}

void McpServer::server_thread_func() {
    try {
        msg("[IDA MCP] Starting HTTP MCP server...\n");
        http_server_ = std::make_unique<httplib::Server>();

        http_server_->Options("/mcp", [](const httplib::Request &req, httplib::Response &res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            res.status = 204;
        });

        http_server_->Get("/mcp", [](const httplib::Request &req, httplib::Response &res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_content(R"({"status": "ok"})", "application/json");
        });

        http_server_->Post("/mcp", [](const httplib::Request &req, httplib::Response &res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Content-Type", "application/json");

            if (!validate_bearer_token(req)) {
                send_auth_error(res);
                msg("[IDA MCP] Unauthorized request\n");
                return;
            }

            try {
                auto body = nlohmann::json::parse(req.body);
                std::string method = body.value("method", "");
                nlohmann::json params = body.value("params", nlohmann::json::object());
                nlohmann::json id = body.value("id", nlohmann::json());

                msg("[IDA MCP] Request: method=%s\n", method.c_str());

                nlohmann::json result;

                if (method == "initialize") {
                    result = handle_initialize(params);
                } else if (method == "tools/list") {
                    result = handle_tools_list(params);
                } else if (method == "tools/call") {
                    result = handle_tool_call(params);
                } else if (method == "notifications/initialized") {
                    msg("[IDA MCP] Client initialized\n");
                    res.status = 200;
                    res.set_content("", "application/json");
                    return;
                } else {
                    msg("[IDA MCP] Unknown method: %s\n", method.c_str());
                    res.status = 400;
                    nlohmann::json error_response;
                    error_response["jsonrpc"] = "2.0";
                    error_response["id"] = id;
                    error_response["error"] = {
                        {"code", -32601},
                        {"message", "Method not found: " + method}
                    };
                    res.set_content(error_response.dump(), "application/json");
                    return;
                }

                nlohmann::json response;
                response["jsonrpc"] = "2.0";
                response["id"] = id;
                response["result"] = result;

                std::string response_str = response.dump();
                msg("[IDA MCP] Response size: %lu bytes\n", response_str.size());
                res.set_content(response_str, "application/json");
            } catch (const std::exception &e) {
                msg("[IDA MCP] Error: %s\n", e.what());
                res.status = 500;
                nlohmann::json error_response;
                error_response["jsonrpc"] = "2.0";
                error_response["error"] = {
                    {"code", -32603},
                    {"message", std::string("Internal error: ") + e.what()}
                };
                res.set_content(error_response.dump(), "application/json");
            }
        });

        msg("[IDA MCP] Server running on http://127.0.0.1:3000/mcp\n");
        msg("[IDA MCP] Bearer Token: %s\n", SESSION_TOKEN.c_str());
        msg("[IDA MCP] Ready for Claude Code connection!\n");

        http_server_->listen("127.0.0.1", 3000);
    } catch (const std::exception &e) {
        msg("[IDA MCP] Server error: %s\n", e.what());
    }
}
