#pragma once

#include <nlohmann/json.hpp>

nlohmann::json handle_initialize(const nlohmann::json &params);

nlohmann::json handle_tools_list(const nlohmann::json &params);

nlohmann::json handle_tool_call(const nlohmann::json &params);
