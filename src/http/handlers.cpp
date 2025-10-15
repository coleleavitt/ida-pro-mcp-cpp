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
    if (!params.contains("name")) {
        throw std::invalid_argument("Missing required parameter: name");
    }

    std::string tool_name;
    try {
        tool_name = params["name"];
    } catch (const nlohmann::json::exception& e) {
        throw std::invalid_argument("Invalid name parameter: " + std::string(e.what()));
    }

    if (tool_name.empty()) {
        throw std::invalid_argument("Tool name cannot be empty");
    }

    nlohmann::json args;
    try {
        args = params.value("arguments", nlohmann::json::object());
    } catch (const nlohmann::json::exception& e) {
        throw std::invalid_argument("Invalid arguments parameter: " + std::string(e.what()));
    }

    return ToolRegistry::instance().call_tool(tool_name, args);
}
