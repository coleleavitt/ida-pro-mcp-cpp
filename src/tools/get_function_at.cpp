#include "tools/get_function_at.hpp"
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

std::string GetFunctionAtTool::get_name() const {
    return "get_function_at";
}

std::string GetFunctionAtTool::get_description() const {
    return "Get information about function at address";
}

nlohmann::json GetFunctionAtTool::get_input_schema() const {
    return {
        {"type", "object"},
        {
            "properties", {
                {
                    "address", {
                        {"type", "integer"},
                        {"description", "Function address"}
                    }
                }
            }
        },
        {"required", nlohmann::json::array({"address"})}
    };
}

nlohmann::json GetFunctionAtTool::execute(const nlohmann::json& args) {
    return execute_sync_wrapper([&]() -> nlohmann::json {
        ea_t address = args.value("address", 0);
        func_t *func = get_func(address);

        std::ostringstream info;
        if (!func) {
            info << "No function at address 0x" << std::hex << address;
        } else {
            qstring name;
            get_func_name(&name, func->start_ea);
            info << "Function: " << name.c_str() << "\n";
            info << "Start: 0x" << std::hex << func->start_ea << "\n";
            info << "End: 0x" << std::hex << func->end_ea << "\n";
            info << "Size: " << std::dec << (func->end_ea - func->start_ea) << " bytes";
        }

        nlohmann::json content_item;
        content_item["type"] = "text";
        content_item["text"] = info.str();

        nlohmann::json result;
        result["content"] = nlohmann::json::array({content_item});
        return result;
    });
}
