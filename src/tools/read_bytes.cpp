#include "tools/read_bytes.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>

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
#include <bytes.hpp>

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

std::string ReadBytesTool::get_name() const {
    return "read_bytes";
}

std::string ReadBytesTool::get_description() const {
    return "Read bytes from database at address";
}

nlohmann::json ReadBytesTool::get_input_schema() const {
    return {
        {"type", "object"},
        {
            "properties", {
                {
                    "address", {
                        {"type", "integer"},
                        {"description", "Address to read from"}
                    }
                },
                {
                    "size", {
                        {"type", "integer"},
                        {"description", "Number of bytes (max 1024)"}
                    }
                }
            }
        },
        {"required", nlohmann::json::array({"address", "size"})}
    };
}

nlohmann::json ReadBytesTool::execute(const nlohmann::json& args) {
    return execute_sync_wrapper([&]() -> nlohmann::json {
        ea_t address = args.value("address", 0);
        size_t size = std::min(static_cast<size_t>(args.value("size", 16)), static_cast<size_t>(1024));

        std::ostringstream output;
        output << "Bytes at 0x" << std::hex << address << ":\n";

        for (size_t i = 0; i < size; i += 16) {
            output << std::hex << std::setfill('0') << std::setw(8) << (address + i) << ": ";
            for (size_t j = 0; j < 16 && (i + j) < size; j++) {
                uint8 byte_val = get_byte(address + i + j);
                output << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte_val) << " ";
            }
            output << "\n";
        }

        nlohmann::json content_item;
        content_item["type"] = "text";
        content_item["text"] = output.str();

        nlohmann::json result;
        result["content"] = nlohmann::json::array({content_item});
        return result;
    });
}
