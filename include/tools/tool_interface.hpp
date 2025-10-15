#pragma once

#include <nlohmann/json.hpp>
#include <string>

class ITool {
public:
    virtual ~ITool() = default;

    virtual std::string get_name() const = 0;

    virtual std::string get_description() const = 0;

    virtual nlohmann::json get_input_schema() const = 0;

    virtual nlohmann::json execute(const nlohmann::json &args) = 0;
};
