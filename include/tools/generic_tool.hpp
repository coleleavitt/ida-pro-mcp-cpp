#pragma once

#include "tool_interface.hpp"
#include <functional>

// Forward declaration - implementation in tool_registry.cpp
// Generic tool wrapper for function-based tools
class GenericTool : public ITool {
private:
    std::string name_;
    std::string description_;
    nlohmann::json schema_;
    std::function<nlohmann::json(const nlohmann::json &)> func_;

public:
    GenericTool(
        std::string name,
        std::string description,
        nlohmann::json schema,
        std::function<nlohmann::json(const nlohmann::json &)> func
    ) : name_(std::move(name)),
        description_(std::move(description)),
        schema_(std::move(schema)),
        func_(std::move(func)) {
    }

    std::string get_name() const override { return name_; }
    std::string get_description() const override { return description_; }
    nlohmann::json get_input_schema() const override { return schema_; }

    nlohmann::json execute(const nlohmann::json &args) override;
};
