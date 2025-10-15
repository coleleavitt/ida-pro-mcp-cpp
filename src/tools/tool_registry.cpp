#include "tools/tool_registry.hpp"
#include "tools/generic_tool.hpp"
#include "tools/all_tools.hpp"
#include "common/ida_helpers.hpp"
#include <vector>

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

// Tool definitions using DRY approach
struct ToolDefinition {
    const char *name;
    const char *description;
    nlohmann::json schema;
    std::function<nlohmann::json(const nlohmann::json &)> function;
};

static const std::vector<ToolDefinition> tool_definitions = {
    // ===== Database/General Tools =====
    {
        "get_database_info",
        "Get information about the loaded IDA database",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_database_info
    },
    {
        "list_functions",
        "List all functions in the database",
        {
            {"type", "object"},
            {
                "properties",
                {{"limit", {{"type", "integer"}, {"default", 100}, {"description", "Max functions to return"}}}}
            },
            {"required", nlohmann::json::array()}
        },
        ida_mcp::list_functions
    },
    {
        "get_function_at",
        "Get information about function at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_function_at
    },
    {
        "read_bytes",
        "Read bytes from database at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address to read from"}}},
                    {"size", {{"type", "integer"}, {"description", "Number of bytes (max 1024)"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "size"})}
        },
        ida_mcp::read_bytes
    },

    // ===== Cross-Reference Tools =====
    {
        "get_xrefs_to",
        "Get all cross-references TO an address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Target address"}}},
                    {
                        "xref_type",
                        {
                            {"type", "string"}, {"enum", nlohmann::json::array({"all", "code", "data"})},
                            {"default", "all"}
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_xrefs_to
    },
    {
        "get_xrefs_from",
        "Get all cross-references FROM an address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Source address"}}},
                    {
                        "xref_type",
                        {
                            {"type", "string"}, {"enum", nlohmann::json::array({"all", "code", "data"})},
                            {"default", "all"}
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_xrefs_from
    },
    {
        "get_callers",
        "Get all functions that call the specified address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_callers
    },
    {
        "get_callees",
        "Get all functions called by the specified address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_callees
    },

    // ===== Name/Symbol Tools =====
    {
        "get_name",
        "Get name at address (including demangled names)",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"demangled", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_name
    },
    {
        "set_name",
        "Set name at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"name", {{"type", "string"}}},
                    {"force", {{"type", "boolean"}, {"default", false}}},
                    {"public", {{"type", "boolean"}, {"default", false}}},
                    {"weak", {{"type", "boolean"}, {"default", false}}},
                    {"auto", {{"type", "boolean"}, {"default", false}}},
                    {"local", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address", "name"})}
        },
        ida_mcp::set_name
    },
    {
        "get_name_ea",
        "Get address by name",
        {
            {"type", "object"},
            {
                "properties", {
                    {"name", {{"type", "string"}}},
                    {"from", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_name_ea
    },

    // ===== Comment Tools =====
    {
        "get_comment",
        "Get comment at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"repeatable", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_comment
    },
    {
        "set_comment",
        "Set comment at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"comment", {{"type", "string"}}},
                    {"repeatable", {{"type", "boolean"}, {"default", false}}},
                    {"function_comment", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address", "comment"})}
        },
        ida_mcp::set_comment
    },

    // ===== String Tools =====
    {
        "get_strings",
        "Get all strings in the database",
        {
            {"type", "object"},
            {"properties", {{"limit", {{"type", "integer"}, {"default", 1000}}}}},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_strings
    },
    {
        "get_string_at",
        "Get string at specific address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_string_at
    },

    // ===== Segment Tools =====
    {
        "get_segments",
        "List all segments",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_segments
    },
    {
        "get_segment_at",
        "Get segment containing address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_segment_at
    },

    // ===== Instruction Analysis Tools =====
    {
        "decode_insn",
        "Decode instruction at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::decode_insn
    },
    {
        "get_disasm_line",
        "Get formatted disassembly line at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_disasm_line
    },
    {
        "generate_disasm_text",
        "Get multiple disassembly lines",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_address", {{"type", "integer"}}},
                    {"end_address", {{"type", "integer"}}},
                    {"max_lines", {{"type", "integer"}, {"default", 50}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"start_address"})}
        },
        ida_mcp::generate_disasm_text
    },

    // ===== Enhanced Function Tools =====
    {
        "get_func_name",
        "Get function name",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"demangled", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_func_name
    },
    {
        "get_func_comment",
        "Get function comment",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"repeatable", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_func_comment
    },
    {
        "get_func_size",
        "Calculate function size",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_func_size
    },
    {
        "get_func_ranges",
        "Get all function ranges (including tails)",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_func_ranges
    },

    // ===== Decompilation Tools (Hex-Rays) =====
    {
        "decompile_function",
        "Decompile function to pseudocode using Hex-Rays decompiler",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}, {"description", "Decompilation flags"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::decompile_function
    },
    {
        "decompile_snippet",
        "Decompile arbitrary code range",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_address", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_address", {{"type", "integer"}, {"description", "End address"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"start_address"})}
        },
        ida_mcp::decompile_snippet
    },
    {
        "generate_microcode",
        "Generate microcode IR for function",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {
                        "maturity",
                        {
                            {"type", "string"},
                            {"default", "MMAT_GLBOPT3"},
                            {"enum", nlohmann::json::array({
                                "MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT",
                                "MMAT_CALLS", "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3"
                            })},
                            {"description", "Microcode maturity level"}
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::generate_microcode
    },
    {
        "get_local_variables",
        "Get local variables from decompiled function",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_local_variables
    },
    {
        "get_ctree",
        "Get C-tree AST structure of decompiled function",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_ctree
    },
    {
        "get_microcode_block",
        "Get detailed microcode for specific basic block",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"block_serial", {{"type", "integer"}, {"default", 0}, {"description", "Block index"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::print_microcode_block
    }
};

// Implementation of GenericTool::execute
nlohmann::json GenericTool::execute(const nlohmann::json &args) {
    return execute_sync_wrapper([&]() -> nlohmann::json {
        try {
            // Validate that args is an object
            if (!args.is_object()) {
                throw std::invalid_argument("Tool arguments must be a JSON object");
            }

            // Call the tool function and get the result data
            nlohmann::json result_data = func_(args);

            // Validate result is a valid JSON object/array
            if (!result_data.is_object() && !result_data.is_array()) {
                throw std::runtime_error("Tool returned invalid JSON type (must be object or array)");
            }

            // Wrap in MCP response format
            nlohmann::json content_item;
            content_item["type"] = "text";
            content_item["text"] = result_data.dump(2);

            nlohmann::json result;
            result["content"] = nlohmann::json::array({content_item});
            return result;
        } catch (const std::invalid_argument &e) {
            nlohmann::json error_content;
            error_content["type"] = "text";
            error_content["text"] = std::string("Invalid arguments: ") + e.what();

            nlohmann::json result;
            result["content"] = nlohmann::json::array({error_content});
            result["isError"] = true;
            return result;
        } catch (const std::runtime_error &e) {
            nlohmann::json error_content;
            error_content["type"] = "text";
            error_content["text"] = std::string("Runtime error: ") + e.what();

            nlohmann::json result;
            result["content"] = nlohmann::json::array({error_content});
            result["isError"] = true;
            return result;
        } catch (const std::exception &e) {
            nlohmann::json error_content;
            error_content["type"] = "text";
            error_content["text"] = std::string("Unexpected error: ") + e.what();

            nlohmann::json result;
            result["content"] = nlohmann::json::array({error_content});
            result["isError"] = true;
            return result;
        }
    });
}

ToolRegistry &ToolRegistry::instance() {
    static ToolRegistry registry;
    return registry;
}

ToolRegistry::ToolRegistry() {
    for (const auto &def: tool_definitions) {
        register_tool(std::make_unique<GenericTool>(
            def.name,
            def.description,
            def.schema,
            def.function
        ));
    }
}

void ToolRegistry::register_tool(std::unique_ptr<ITool> tool) {
    ITool *ptr = tool.get();
    tool_map_[ptr->get_name()] = ptr;
    tools_.push_back(std::move(tool));
}

nlohmann::json ToolRegistry::get_tools_list() const {
    nlohmann::json tools = nlohmann::json::array();

    for (const auto &tool: tools_) {
        nlohmann::json tool_def;
        tool_def["name"] = tool->get_name();
        tool_def["description"] = tool->get_description();
        tool_def["inputSchema"] = tool->get_input_schema();
        tools.push_back(tool_def);
    }

    msg("[IDA MCP] Returning %lu tools\n", tools.size());

    nlohmann::json result;
    result["tools"] = tools;
    return result;
}

nlohmann::json ToolRegistry::call_tool(const std::string &name, const nlohmann::json &args) {
    if (name.empty()) {
        nlohmann::json error_result;
        error_result["content"] = nlohmann::json::array({
            {{"type", "text"}, {"text", "Tool name cannot be empty"}}
        });
        error_result["isError"] = true;
        return error_result;
    }

    auto it = tool_map_.find(name);
    if (it == tool_map_.end()) {
        // List available tools in error message
        std::string available_tools = "Available tools: ";
        for (size_t i = 0; i < tools_.size(); ++i) {
            if (i > 0) available_tools += ", ";
            available_tools += tools_[i]->get_name();
        }

        nlohmann::json error_result;
        error_result["content"] = nlohmann::json::array({
            {{"type", "text"}, {"text", "Unknown tool: " + name + ". " + available_tools}}
        });
        error_result["isError"] = true;
        return error_result;
    }

    msg("[IDA MCP] Tool call: %s\n", name.c_str());
    return it->second->execute(args);
}
