#include "tools/database_info.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sstream>

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
#include <funcs.hpp>
#include <segment.hpp>

template<typename Func>
auto execute_sync_wrapper(Func &&func) {
    using RetType = decltype(func());
    RetType result;
    struct exec_helper : public exec_request_t {
        Func &f;
        RetType &res;

        exec_helper(Func &func, RetType &result) : f(func), res(result) {
        }

        ssize_t idaapi execute() override {
            res = f();
            return 0;
        }
    };
    exec_helper helper(func, result);
    execute_sync(helper, MFF_READ);
    return result;
}

std::string DatabaseInfoTool::get_name() const {
    return "get_database_info";
}

std::string DatabaseInfoTool::get_description() const {
    return "Get information about the loaded IDA database";
}

nlohmann::json DatabaseInfoTool::get_input_schema() const {
    return {
        {"type", "object"},
        {"properties", nlohmann::json::object()},
        {"required", nlohmann::json::array()}
    };
}

nlohmann::json DatabaseInfoTool::execute(const nlohmann::json& args) {
    return execute_sync_wrapper([&]() -> nlohmann::json {
        char buf[QMAXPATH];
        get_input_file_path(buf, sizeof(buf));
        std::ostringstream oss;
        oss << "Database: " << buf << "\n";
        oss << "Functions: " << get_func_qty() << "\n";
        oss << "Segments: " << get_segm_qty();

        nlohmann::json content_item;
        content_item["type"] = "text";
        content_item["text"] = oss.str();

        nlohmann::json result;
        result["content"] = nlohmann::json::array({content_item});
        return result;
    });
}
