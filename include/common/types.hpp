#pragma once

#include <nlohmann/json.hpp>
#include <functional>

using ToolHandler = std::function<nlohmann::json(const nlohmann::json&)>;
