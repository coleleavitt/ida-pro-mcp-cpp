#include "tools/list_functions.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

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
#include <name.hpp>

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

std::string ListFunctionsTool::get_name() const {
    return "list_functions";
}

std::string ListFunctionsTool::get_description() const {
    return "List all functions in the database";
}

nlohmann::json ListFunctionsTool::get_input_schema() const {
    return {
        {"type", "object"},
        {
            "properties", {
                {
                    "limit", {
                        {"type", "integer"},
                        {"description", "Max functions to return"}
                    }
                }
            }
        },
        {"required", nlohmann::json::array()}
    };
}

nlohmann::json ListFunctionsTool::execute(const nlohmann::json& args) {
    return execute_sync_wrapper([&]() -> nlohmann::json {
        size_t limit = args.value("limit", 100);
        std::ostringstream output;
        output << "Functions:\n";

        for (size_t i = 0; i < get_func_qty() && i < limit; i++) {
            if (func_t *func = getn_func(i)) {
                qstring name;
                get_func_name(&name, func->start_ea);
                output << "0x" << std::hex << func->start_ea << ": " << name.c_str() << "\n";
            }
        }

        nlohmann::json content_item;
        content_item["type"] = "text";
        content_item["text"] = output.str();

        nlohmann::json result;
        result["content"] = nlohmann::json::array({content_item});
        return result;
    });
}
