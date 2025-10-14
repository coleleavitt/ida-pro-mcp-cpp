#pragma once

#include "tool_interface.hpp"
#include <memory>
#include <vector>
#include <unordered_map>

class ToolRegistry {
public:
    static ToolRegistry& instance();
    
    void register_tool(std::unique_ptr<ITool> tool);
    nlohmann::json get_tools_list() const;
    nlohmann::json call_tool(const std::string& name, const nlohmann::json& args);
    
private:
    ToolRegistry();
    std::vector<std::unique_ptr<ITool>> tools_;
    std::unordered_map<std::string, ITool*> tool_map_;
};
