#include <httplib.h>
#include <nlohmann/json.hpp>
#include "http/server.hpp"

#define DONT_DEFINE_HEXRAYS 1
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

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

class IdaMcpPlugmod : public plugmod_t {
public:
    IdaMcpPlugmod() {
        msg("[IDA MCP] Plugin loaded - Press Ctrl+Shift+M to start server\n");
    }

    ~IdaMcpPlugmod() override {
        McpServer::instance().stop();
    }

    bool idaapi run(size_t arg) override {
        McpServer::instance().start();
        return true;
    }
};

static plugmod_t * idaapi init() {
    return new IdaMcpPlugmod();
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI | PLUGIN_FIX,
    init, nullptr, nullptr,
    "IDA Pro MCP Server",
    "HTTP MCP server with Bearer auth for Claude Code",
    "IDA MCP Server",
    "Ctrl-Shift-M"
};
