#pragma once

#define DONT_DEFINE_HEXRAYS 1
#include <ida.hpp>

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

// Template wrapper to execute functions in IDA's main thread
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

// Helper function to convert bytes to hex string
inline std::string bytes_to_hex(const uint8_t* data, size_t size) {
    std::string hex_str;
    hex_str.reserve(size * 2);
    const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < size; ++i) {
        hex_str += hex_chars[(data[i] >> 4) & 0xF];
        hex_str += hex_chars[data[i] & 0xF];
    }
    return hex_str;
}
