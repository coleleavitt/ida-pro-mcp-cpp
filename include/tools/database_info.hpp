#pragma once

#include "tool_interface.hpp"

class DatabaseInfoTool : public ITool {
public:
    std::string get_name() const override;
    std::string get_description() const override;
    nlohmann::json get_input_schema() const override;
    nlohmann::json execute(const nlohmann::json& args) override;
};
