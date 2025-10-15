#include "http/handlers.hpp"
#include "tools/tool_registry.hpp"

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

nlohmann::json handle_initialize(const nlohmann::json &params) {
    nlohmann::json response;
    response["protocolVersion"] = "2024-11-05";
    response["serverInfo"] = {
        {"name", "ida-pro-mcp-server"},
        {"version", "1.0.0"}
    };
    response["capabilities"] = {
        {"tools", nlohmann::json::object()}
    };

    msg("[IDA MCP] Received initialize request\n");
    msg("[IDA MCP] Responding with capabilities: tools\n");

    return response;
}

nlohmann::json handle_tools_list(const nlohmann::json &params) {
    return ToolRegistry::instance().get_tools_list();
}

nlohmann::json handle_tool_call(const nlohmann::json &params) {
    std::string tool_name = params["name"];
    nlohmann::json args = params.value("arguments", nlohmann::json::object());
    return ToolRegistry::instance().call_tool(tool_name, args);
}
