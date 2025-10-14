#include "tools/tool_registry.hpp"
#include "tools/database_info.hpp"
#include "tools/list_functions.hpp"
#include "tools/get_function_at.hpp"
#include "tools/read_bytes.hpp"

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

ToolRegistry& ToolRegistry::instance() {
    static ToolRegistry registry;
    return registry;
}

ToolRegistry::ToolRegistry() {
    register_tool(std::make_unique<DatabaseInfoTool>());
    register_tool(std::make_unique<ListFunctionsTool>());
    register_tool(std::make_unique<GetFunctionAtTool>());
    register_tool(std::make_unique<ReadBytesTool>());
}

void ToolRegistry::register_tool(std::unique_ptr<ITool> tool) {
    ITool* ptr = tool.get();
    tool_map_[ptr->get_name()] = ptr;
    tools_.push_back(std::move(tool));
}

nlohmann::json ToolRegistry::get_tools_list() const {
    nlohmann::json tools = nlohmann::json::array();
    
    for (const auto& tool : tools_) {
        nlohmann::json tool_def;
        tool_def["name"] = tool->get_name();
        tool_def["description"] = tool->get_description();
        tool_def["inputSchema"] = tool->get_input_schema();
        tools.push_back(tool_def);
    }
    
    msg("[IDA MCP] Returning %lu tools\n", tools.size());
    
    nlohmann::json result;
    result["tools"] = tools;
    return result;
}

nlohmann::json ToolRegistry::call_tool(const std::string& name, const nlohmann::json& args) {
    auto it = tool_map_.find(name);
    if (it == tool_map_.end()) {
        nlohmann::json error_result;
        error_result["content"] = nlohmann::json::array({
            {{"type", "text"}, {"text", "Unknown tool: " + name}}
        });
        error_result["isError"] = true;
        return error_result;
    }
    
    msg("[IDA MCP] Tool call: %s\n", name.c_str());
    return it->second->execute(args);
}
