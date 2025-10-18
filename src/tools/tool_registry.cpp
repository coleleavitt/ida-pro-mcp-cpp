#include "tools/tool_registry.hpp"
#include "tools/generic_tool.hpp"
#include "tools/all_tools.hpp"
#include "common/ida_helpers.hpp"

// Additional includes for new tools
#include <vector>
#include <string>
#include <sstream>

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
                    {"size", {{"type", "integer"}, {"description", "Number of bytes (max 16384)"}}}
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
        "search_decompiled",
        "Search for functions containing regex pattern in decompiled code",
        {
            {"type", "object"},
            {
                "properties", {
                    {"pattern", {{"type", "string"}, {"description", "Regex pattern to search for"}}},
                    {"limit", {{"type", "integer"}, {"default", 100}, {"description", "Maximum number of results"}}}
                }
            },
            {"required", nlohmann::json::array({"pattern"})}
        },
        ida_mcp::search_decompiled
    },
    {
        "search_disasm",
        "Search for functions containing regex pattern in disassembly",
        {
            {"type", "object"},
            {
                "properties", {
                    {"pattern", {{"type", "string"}, {"description", "Regex pattern to search for"}}},
                    {"limit", {{"type", "integer"}, {"default", 100}, {"description", "Maximum number of results"}}}
                }
            },
            {"required", nlohmann::json::array({"pattern"})}
        },
        ida_mcp::search_disasm
    },
    {
        "get_objc_classes",
        "Get Objective-C classes from the binary",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_objc_classes
    },
    {
        "get_objc_selectors",
        "Get Objective-C selectors from objc_msgSend calls",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_objc_selectors
    },
    {
        "get_entitlements",
        "Get iOS app entitlements",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_entitlements
    },
    {
        "get_codesignature",
        "Get code signature information",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_codesignature
    },
    {
        "demangle_swift_symbols",
        "Demangle Swift mangled symbol names",
        {
            {"type", "object"},
            {
                "properties", {
                    {"mangled_name", {{"type", "string"}, {"description", "Mangled Swift symbol name"}}}
                }
            },
            {"required", nlohmann::json::array({"mangled_name"})}
        },
        ida_mcp::demangle_swift_symbols
    },
    {
        "get_macho_header",
        "Get Mach-O file header information",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_macho_header
    },
    {
        "get_framework_info",
        "Get information about iOS frameworks used",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        ida_mcp::get_framework_info
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
                            {
                                "enum", nlohmann::json::array({
                                    "MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT",
                                    "MMAT_CALLS", "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3"
                                })
                            },
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
    },

    // ===== Type System Tools =====
    {
        "get_type",
        "Get type information at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_type
    },
    {
        "set_type",
        "Apply type to address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"type_string", {{"type", "string"}, {"description", "Type declaration string"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"address", "type_string"})}
        },
        ida_mcp::set_type
    },
    {
        "get_tinfo",
        "Get detailed tinfo_t object information",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_tinfo_details
    },
    {
        "parse_type_declaration",
        "Parse C/C++/Objective-C type declaration",
        {
            {"type", "object"},
            {
                "properties", {
                    {"declaration", {{"type", "string"}, {"description", "Type declaration"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"declaration"})}
        },
        ida_mcp::parse_type_declaration
    },
    {
        "print_type",
        "Format type as string at address",
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
        ida_mcp::print_type_at
    },
    {
        "get_type_size",
        "Get size of type at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_type_size
    },
    {
        "get_struct_by_name",
        "Get structure definition by name",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Structure name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_struct_by_name
    },
    {
        "get_struct_members",
        "List all members of a structure",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Structure name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_struct_members
    },
    {
        "get_struct_member",
        "Get structure member at specific offset",
        {
            {"type", "object"},
            {
                "properties", {
                    {"name", {{"type", "string"}, {"description", "Structure name"}}},
                    {"offset", {{"type", "integer"}, {"description", "Member offset"}}}
                }
            },
            {"required", nlohmann::json::array({"name", "offset"})}
        },
        ida_mcp::get_struct_member_at_offset
    },
    {
        "get_enum_members",
        "List all members of an enum",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Enum name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_enum_members
    },
    {
        "get_function_type",
        "Get function signature and arguments",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_function_type
    },
    {
        "set_function_type",
        "Set function signature",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}}},
                    {"type_string", {{"type", "string"}, {"description", "Function type declaration"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "type_string"})}
        },
        ida_mcp::set_function_type
    },
    {
        "get_return_type",
        "Get function return type",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_function_return_type
    },
    {
        "get_named_type",
        "Get type from type library by name",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Type name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_named_type
    },
    {
        "get_numbered_type",
        "Get type by ordinal number",
        {
            {"type", "object"},
            {"properties", {{"ordinal", {{"type", "integer"}, {"description", "Type ordinal"}}}}},
            {"required", nlohmann::json::array({"ordinal"})}
        },
        ida_mcp::get_numbered_type
    },
    {
        "parse_objc_declaration",
        "Parse Objective-C type declaration",
        {
            {"type", "object"},
            {"properties", {{"declaration", {{"type", "string"}, {"description", "Objective-C declaration"}}}}},
            {"required", nlohmann::json::array({"declaration"})}
        },
        ida_mcp::parse_objc_declaration
    },
    {
        "parse_declarations",
        "Parse multiple type declarations in specified language",
        {
            {"type", "object"},
            {
                "properties", {
                    {"declarations", {{"type", "string"}, {"description", "Type declarations"}}},
                    {
                        "language",
                        {
                            {"type", "string"},
                            {"enum", nlohmann::json::array({"C", "C++", "CPP", "OBJC", "Objective-C"})},
                            {"default", "C"}
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"declarations"})}
        },
        ida_mcp::parse_declarations
    },

    // ===== Control Flow Graph Tools =====
    {
        "get_flowchart",
        "Get function control flow graph with basic blocks",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_flowchart
    },
    {
        "get_basic_blocks",
        "List all basic blocks in function",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_basic_blocks
    },
    {
        "get_basic_block_at",
        "Get basic block containing address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_basic_block_at
    },
    {
        "get_block_succs",
        "Get successors of basic block",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"block_id", {{"type", "integer"}, {"description", "Block ID"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "block_id"})}
        },
        ida_mcp::get_block_succs
    },
    {
        "get_block_preds",
        "Get predecessors of basic block",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"block_id", {{"type", "integer"}, {"description", "Block ID"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "block_id"})}
        },
        ida_mcp::get_block_preds
    },
    {
        "get_block_type",
        "Get block type (normal/ret/noret/etc)",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"block_id", {{"type", "integer"}, {"description", "Block ID"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "block_id"})}
        },
        ida_mcp::get_block_type
    },

    // ===== Call Graph Tools =====
    {
        "generate_call_graph",
        "Generate function call graph",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"depth", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::generate_call_graph
    },
    {
        "get_caller_graph",
        "Get callers recursively",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"depth", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_caller_graph
    },
    {
        "get_callee_graph",
        "Get callees recursively",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"depth", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_callee_graph
    },

    // ===== Stack Frame Analysis Tools =====
    {
        "get_frame",
        "Get stack frame structure",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_frame
    },
    {
        "get_frame_size",
        "Get total frame size",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_frame_size
    },
    {
        "get_stack_vars",
        "Get stack variables",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_stack_vars
    },
    {
        "get_stack_var_at",
        "Get stack variable at offset",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"offset", {{"type", "integer"}, {"description", "Stack offset"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "offset"})}
        },
        ida_mcp::get_stack_var_at
    },
    {
        "get_frame_args",
        "Get function arguments from frame",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_frame_args
    },
    {
        "get_frame_locals",
        "Get local variables from frame",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_frame_locals
    },

    // ===== Import/Export Tables Tools =====
    {
        "get_import_modules",
        "List import modules",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_import_modules
    },
    {
        "get_imports",
        "Get all imports from module",
        {
            {"type", "object"},
            {"properties", {{"module_index", {{"type", "integer"}, {"description", "Module index"}}}}},
            {"required", nlohmann::json::array({"module_index"})}
        },
        ida_mcp::get_imports
    },
    {
        "enum_imports",
        "Enumerate imports with callback",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::enum_imports
    },
    {
        "get_export_count",
        "Get number of exports",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_export_count
    },
    {
        "get_exports",
        "Get all exports",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_exports
    },

    // ===== Entry Points Tools =====
    {
        "get_entry_points",
        "Get all entry points",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_entry_points
    },
    {
        "get_entry_point",
        "Get entry point by ordinal",
        {
            {"type", "object"},
            {"properties", {{"ordinal", {{"type", "integer"}, {"description", "Entry point ordinal"}}}}},
            {"required", nlohmann::json::array({"ordinal"})}
        },
        ida_mcp::get_entry_point
    },
    {
        "get_entry_name",
        "Get entry point name",
        {
            {"type", "object"},
            {"properties", {{"ordinal", {{"type", "integer"}, {"description", "Entry point ordinal"}}}}},
            {"required", nlohmann::json::array({"ordinal"})}
        },
        ida_mcp::get_entry_name
    },

    // ===== Pattern Search Tools =====
    {
        "search_binary",
        "Binary pattern search",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"pattern", {{"type", "string"}, {"description", "Binary pattern"}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "pattern"})}
        },
        ida_mcp::search_binary
    },
    {
        "find_pattern",
        "Search for byte pattern",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"pattern", {{"type", "string"}, {"description", "Binary pattern"}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"limit", {{"type", "integer"}, {"default", 100}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "pattern"})}
        },
        ida_mcp::find_pattern
    },
    {
        "search_text",
        "Text string search",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"text", {{"type", "string"}, {"description", "Search text"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "text"})}
        },
        ida_mcp::search_text
    },

    // ===== Fixups/Relocations Tools =====
    {
        "get_fixup",
        "Get fixup/relocation at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_fixup
    },
    {
        "get_all_fixups",
        "Get all fixups in range",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_ea", {{"type", "integer"}, {"description", "End address"}}},
                    {"limit", {{"type", "integer"}, {"default", 1000}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "end_ea"})}
        },
        ida_mcp::get_all_fixups
    },
    {
        "contains_fixups",
        "Check if range contains fixups",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_ea", {{"type", "integer"}, {"description", "End address"}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "end_ea"})}
        },
        ida_mcp::contains_fixups
    },

    // ===== Jump Tables Tools =====
    {
        "get_jump_table",
        "Get jump table at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Jump table address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_jump_table
    },
    {
        "get_switch_info",
        "Get switch statement info",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Switch instruction address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_switch_info
    },

    // ===== Advanced Demangling Tools =====
    {
        "demangle_name",
        "Demangle C++/Objective-C name",
        {
            {"type", "object"},
            {
                "properties", {
                    {"name", {{"type", "string"}, {"description", "Mangled name"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::demangle_name
    },
    {
        "demangle_type",
        "Demangle type string",
        {
            {"type", "object"},
            {
                "properties", {
                    {"type_string", {{"type", "string"}, {"description", "Mangled type"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"type_string"})}
        },
        ida_mcp::demangle_type
    },

    // ===== Operand Analysis Tools =====
    {
        "get_operand_type",
        "Get instruction operand type",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                    {"operand_num", {{"type", "integer"}, {"description", "Operand number"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "operand_num"})}
        },
        ida_mcp::get_operand_type
    },
    {
        "get_operand_value",
        "Get instruction operand value",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                    {"operand_num", {{"type", "integer"}, {"description", "Operand number"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "operand_num"})}
        },
        ida_mcp::get_operand_value
    },
    {
        "get_canon_feature",
        "Get canonical instruction features",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Instruction address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_canon_feature
    },

    // ===== Data Analysis Tools =====
    {
        "get_data_type",
        "Get data type at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_data_type
    },
    {
        "get_array_info",
        "Get array information",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Array address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_array_info
    },
    {
        "get_struc_id",
        "Get structure ID at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_struc_id
    },
    {
        "is_code",
        "Check if address contains code",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_code
    },
    {
        "is_data",
        "Check if address contains data",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_data
    },
    {
        "is_unknown",
        "Check if address is unexplored",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_unknown
    },

    // ===== Database Metadata Tools =====
    {
        "get_imagebase",
        "Get image base address",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_imagebase
    },
    {
        "get_root_filename",
        "Get root filename without path",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_root_filename
    },
    {
        "get_input_file_path",
        "Get full input file path",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_input_file_path
    },

    // ===== Function Modification Tools =====
    {
        "set_func_name",
        "Rename function",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"name", {{"type", "string"}, {"description", "New name"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "name"})}
        },
        ida_mcp::set_func_name
    },
    {
        "del_func",
        "Delete function",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::del_func
    },
    {
        "add_func",
        "Create new function",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end", {{"type", "integer"}}}
                }
            },
            {"required", nlohmann::json::array({"start"})}
        },
        ida_mcp::add_func
    },
    {
        "set_func_start",
        "Set function start address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"new_start", {{"type", "integer"}, {"description", "New start address"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "new_start"})}
        },
        ida_mcp::set_func_start
    },
    {
        "set_func_end",
        "Set function end address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"new_end", {{"type", "integer"}, {"description", "New end address"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "new_end"})}
        },
        ida_mcp::set_func_end
    },
    {
        "reanalyze_function",
        "Force function reanalysis",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::reanalyze_function
    },

    // ===== Cross-Reference Enhancement Tools =====
    {
        "add_cref",
        "Add code cross-reference",
        {
            {"type", "object"},
            {
                "properties", {
                    {"from", {{"type", "integer"}, {"description", "Source address"}}},
                    {"to", {{"type", "integer"}, {"description", "Target address"}}},
                    {"type", {{"type", "integer"}, {"default", 16}}}
                }
            },
            {"required", nlohmann::json::array({"from", "to"})}
        },
        ida_mcp::add_cref
    },
    {
        "add_dref",
        "Add data cross-reference",
        {
            {"type", "object"},
            {
                "properties", {
                    {"from", {{"type", "integer"}, {"description", "Source address"}}},
                    {"to", {{"type", "integer"}, {"description", "Target address"}}},
                    {"type", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"from", "to"})}
        },
        ida_mcp::add_dref
    },
    {
        "del_cref",
        "Delete code cross-reference",
        {
            {"type", "object"},
            {
                "properties", {
                    {"from", {{"type", "integer"}, {"description", "Source address"}}},
                    {"to", {{"type", "integer"}, {"description", "Target address"}}},
                    {"expand", {{"type", "boolean"}, {"default", true}}}
                }
            },
            {"required", nlohmann::json::array({"from", "to"})}
        },
        ida_mcp::del_cref
    },
    {
        "del_dref",
        "Delete data cross-reference",
        {
            {"type", "object"},
            {
                "properties", {
                    {"from", {{"type", "integer"}, {"description", "Source address"}}},
                    {"to", {{"type", "integer"}, {"description", "Target address"}}}
                }
            },
            {"required", nlohmann::json::array({"from", "to"})}
        },
        ida_mcp::del_dref
    },

    // ===== Patching Tools =====
    {
        "patch_byte",
        "Patch byte at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"value", {{"description", "Byte value (integer or hex string like '0xFF')"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "value"})}
        },
        ida_mcp::patch_byte
    },
    {
        "patch_word",
        "Patch word at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"value", {{"description", "Word value (integer or hex string like '0xFFFF')"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "value"})}
        },
        ida_mcp::patch_word
    },
    {
        "patch_dword",
        "Patch dword at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"value", {{"description", "Dword value (integer or hex string like '0x14003A3E')"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "value"})}
        },
        ida_mcp::patch_dword
    },
    {
        "patch_qword",
        "Patch qword at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"value", {{"description", "Qword value (integer or hex string like '0xD65F03C0')"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "value"})}
        },
        ida_mcp::patch_qword
    },
    {
        "get_original_byte",
        "Get original byte value",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_original_byte
    },
    {
        "revert_byte",
        "Revert byte to original",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::revert_byte
    },
    {
        "visit_patched_bytes",
        "Get all patched bytes in range",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"default", 0}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"limit", {{"type", "integer"}, {"default", 1000}}}
                }
            },
            {"required", nlohmann::json::array()}
        },
        ida_mcp::visit_patched_bytes
    },

    // ===== Search Enhancement Tools =====
    {
        "find_binary_ex",
        "Enhanced binary pattern search",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"pattern", {{"type", "string"}, {"description", "Binary pattern"}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "pattern"})}
        },
        ida_mcp::find_binary_ex
    },
    {
        "find_text_ex",
        "Enhanced text search",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"text", {{"type", "string"}, {"description", "Search text"}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "text"})}
        },
        ida_mcp::find_text_ex
    },
    {
        "find_all_text",
        "Find all occurrences of text",
        {
            {"type", "object"},
            {
                "properties", {
                    {"text", {{"type", "string"}, {"description", "Search text"}}},
                    {"start_ea", {{"type", "integer"}, {"default", 0}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"limit", {{"type", "integer"}, {"default", 100}}},
                    {"flags", {{"type", "integer"}, {"default", 1}}}
                }
            },
            {"required", nlohmann::json::array({"text"})}
        },
        ida_mcp::find_all_text
    },
    {
        "find_next_addr",
        "Find next defined address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::find_next_addr
    },


    // ===== Disassembly Output Tools =====
    {
        "gen_disasm_text",
        "Generate disassembly text for range",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_ea", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_ea", {{"type", "integer"}, {"description", "End address"}}},
                    {"as_stack", {{"type", "boolean"}, {"default", false}}}
                }
            },
            {"required", nlohmann::json::array({"start_ea", "end_ea"})}
        },
        ida_mcp::gen_disasm_text
    },
    {
        "tag_remove",
        "Remove color tags from text",
        {
            {"type", "object"},
            {"properties", {{"text", {{"type", "string"}, {"description", "Text with tags"}}}}},
            {"required", nlohmann::json::array({"text"})}
        },
        ida_mcp::tag_remove
    },
    {
        "generate_disasm_file",
        "Export disassembly to file",
        {
            {"type", "object"},
            {
                "properties", {
                    {"path", {{"type", "string"}, {"description", "Output file path"}}},
                    {"start_ea", {{"type", "integer"}}},
                    {"end_ea", {{"type", "integer"}}},
                    {"flags", {{"type", "integer"}, {"default", 0}}}
                }
            },
            {"required", nlohmann::json::array({"path"})}
        },
        ida_mcp::generate_disasm_file
    },


    // ===== Plugin/Processor Info Tools =====
    {
        "get_idp_name",
        "Get processor name",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_idp_name
    },
    {
        "get_abi_name",
        "Get ABI/calling convention name",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_abi_name
    },
    {
        "get_plugin_options",
        "Get plugin options",
        {
            {"type", "object"},
            {"properties", {{"plugin_name", {{"type", "string"}, {"description", "Plugin name"}}}}},
            {"required", nlohmann::json::array({"plugin_name"})}
        },
        ida_mcp::get_plugin_options
    },

    // ===== Debugging Tools =====
    {
        "set_bpt",
        "Set breakpoint at address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"size", {{"type", "integer"}, {"default", 0}, {"description", "Breakpoint size"}}},
                    {"type", {{"type", "integer"}, {"default", 0}, {"description", "Breakpoint type (0=soft, 1=hard)"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::set_bpt
    },
    {
        "del_bpt",
        "Delete breakpoint at address",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::del_bpt
    },
    {
        "enable_bpt",
        "Enable or disable breakpoint",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Address"}}},
                    {"enable", {{"type", "boolean"}, {"default", true}, {"description", "Enable breakpoint"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::enable_bpt
    },
    {
        "get_bpt",
        "Get breakpoint information",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_bpt
    },
    {
        "get_thread_qty",
        "Get number of threads",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_thread_qty
    },
    {
        "get_threads",
        "Get all threads",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_threads
    },
    {
        "select_thread",
        "Select active thread",
        {
            {"type", "object"},
            {"properties", {{"thread_id", {{"type", "integer"}, {"description", "Thread ID"}}}}},
            {"required", nlohmann::json::array({"thread_id"})}
        },
        ida_mcp::select_thread
    },
    {
        "start_process",
        "Start debugging process",
        {
            {"type", "object"},
            {
                "properties", {
                    {"path", {{"type", "string"}, {"default", ""}, {"description", "Executable path"}}},
                    {"args", {{"type", "string"}, {"default", ""}, {"description", "Command line arguments"}}},
                    {"working_dir", {{"type", "string"}, {"default", ""}, {"description", "Working directory"}}}
                }
            },
            {"required", nlohmann::json::array()}
        },
        ida_mcp::start_process
    },
    {
        "exit_process",
        "Exit debugging process",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::exit_process
    },
    {
        "suspend_process",
        "Suspend debugging process",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::suspend_process
    },
    {
        "resume_process",
        "Resume debugging process",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::resume_process
    },
    {
        "step_into",
        "Step into instruction",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::step_into
    },
    {
        "step_over",
        "Step over instruction",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::step_over
    },
    {
        "step_until_ret",
        "Step until return",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::step_until_ret
    },
    {
        "run_to",
        "Run until specified address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Target address"}}},
                    {"pid", {{"type", "integer"}, {"description", "Process ID (optional)"}}},
                    {"tid", {{"type", "integer"}, {"description", "Thread ID (optional)"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::run_to
    },

    // ===== Script Execution Tools =====
    {
        "execute_idc_script",
        "Execute an IDC script file",
        {
            {"type", "object"},
            {
                "properties", {
                    {"script_path", {{"type", "string"}, {"description", "Path to IDC script file"}}},
                    {
                        "function_name",
                        {{"type", "string"}, {"default", "main"}, {"description", "Function to call (default: main)"}}
                    }
                }
            },
            {"required", nlohmann::json::array({"script_path"})}
        },
        ida_mcp::execute_idc_script
    },
    {
        "execute_python_script",
        "Execute a Python script file",
        {
            {"type", "object"},
            {
                "properties", {
                    {"script_path", {{"type", "string"}, {"description", "Path to Python script file"}}},
                    {"args", {{"type", "string"}, {"description", "Arguments to pass to script"}}}
                }
            },
            {"required", nlohmann::json::array({"script_path"})}
        },
        ida_mcp::execute_python_script
    },
    {
        "eval_python_code",
        "Evaluate Python code string",
        {
            {"type", "object"},
            {
                "properties", {
                    {"code", {{"type", "string"}, {"description", "Python code to execute"}}},
                    {"args", {{"type", "string"}, {"description", "Arguments to pass"}}}
                }
            },
            {"required", nlohmann::json::array({"code"})}
        },
        ida_mcp::eval_python_code
    },

    // ===== Memory Access Tools =====
    {
        "read_memory",
        "Read memory from debugged process",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Memory address to read from"}}},
                    {
                        "size",
                        {{"type", "integer"}, {"default", 256}, {"description", "Number of bytes to read (max 65536)"}}
                    }
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        [](const nlohmann::json &args) -> nlohmann::json {
            if (!args.contains("address")) {
                throw std::invalid_argument("Missing required parameter: address");
            }

            ea_t address = args["address"];
            size_t size = args.value("size", 256);

            if (size > 65536) {
                throw std::runtime_error("Size exceeds maximum of 65536 bytes");
            }

            std::vector<uint8_t> buffer(size);
            ssize_t bytes_read = read_dbg_memory(address, buffer.data(), size);

            if (bytes_read < 0) {
                throw std::runtime_error(
                    "Failed to read memory at address 0x" + std::to_string(static_cast<uint64_t>(address)));
            }

            buffer.resize(bytes_read);

            nlohmann::json result;
            result["address"] = static_cast<uint64_t>(address);
            result["requested_size"] = size;
            result["bytes_read"] = bytes_read;
            result["data"] = buffer;

            return result;
        }
    },
    {
        "write_memory",
        "Write memory to debugged process",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Memory address to write to"}}},
                    {"data", {{"description", "Data to write (array of bytes or hex string)"}}}
                }
            },
            {"required", nlohmann::json::array({"address", "data"})}
        },
        [](const nlohmann::json &args) -> nlohmann::json {
            if (!args.contains("address") || !args.contains("data")) {
                throw std::invalid_argument("Missing required parameters: address, data");
            }

            ea_t address = args["address"];
            std::vector<uint8_t> data;

            if (args["data"].is_array()) {
                data = args["data"].get<std::vector<uint8_t> >();
            } else if (args["data"].is_string()) {
                std::string hex_str = args["data"];
                if (hex_str.size() % 2 != 0) {
                    throw std::invalid_argument("Hex string must have even length");
                }
                for (size_t i = 0; i < hex_str.size(); i += 2) {
                    std::string byte_str = hex_str.substr(i, 2);
                    data.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
                }
            } else {
                throw std::invalid_argument("Data must be an array of bytes or a hex string");
            }

            if (data.empty()) {
                throw std::invalid_argument("Data cannot be empty");
            }

            if (data.size() > 65536) {
                throw std::runtime_error("Data size exceeds maximum of 65536 bytes");
            }

            ssize_t bytes_written = write_dbg_memory(address, data.data(), data.size());

            if (bytes_written < 0) {
                throw std::runtime_error(
                    "Failed to write memory at address 0x" + std::to_string(static_cast<uint64_t>(address)));
            }

            nlohmann::json result;
            result["address"] = static_cast<uint64_t>(address);
            result["bytes_written"] = bytes_written;
            result["requested_size"] = data.size();
            result["success"] = (bytes_written == static_cast<ssize_t>(data.size()));

            return result;
        }
    },
    {
        "get_memory_info",
        "Get memory region information from debugged process",
        {
            {"type", "object"},
            {"properties", nlohmann::json::object()},
            {"required", nlohmann::json::array()}
        },
        [](const nlohmann::json &args) -> nlohmann::json {
            meminfo_vec_t ranges;
            int count = get_dbg_memory_info(&ranges);

            nlohmann::json memory_regions = nlohmann::json::array();

            for (const auto &range: ranges) {
                nlohmann::json region;
                region["start_ea"] = static_cast<uint64_t>(range.start_ea);
                region["end_ea"] = static_cast<uint64_t>(range.end_ea);
                region["size"] = static_cast<uint64_t>(range.size());
                region["name"] = range.name.c_str();
                region["class"] = range.sclass.c_str();
                region["sbase"] = static_cast<uint64_t>(range.sbase);
                region["bitness"] = range.bitness;
                region["perm"] = range.perm;

                memory_regions.push_back(region);
            }

            nlohmann::json result;
            result["count"] = count;
            result["memory_regions"] = memory_regions;

            return result;
        }
    },
    // ===== HEX-RAYS ADVANCED TOOLS =====
    {
        "install_hexrays_callback",
        "Initialize Hex-Rays callback support",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::install_hexrays_callback
    },
    {
        "modify_ctree",
        "Modify C-tree structure",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"operation", {{"type", "string"}, {"description", "Modification operation"}}}
                }
            },
            {"required", {"address", "operation"}}
        },
        ida_mcp::modify_ctree
    },
    {
        "get_ctree_item",
        "Get C-tree item at specific address",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"item_address", {{"type", "integer"}, {"description", "Item address within function"}}}
                }
            },
            {"required", {"address", "item_address"}}
        },
        ida_mcp::get_ctree_item
    },
    {
        "get_microcode",
        "Get microcode at specific maturity level",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {
                        "maturity",
                        {
                            {"type", "string"},
                            {
                                "description",
                                "Maturity level (MMAT_GENERATED, MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2, MMAT_GLBOPT3, MMAT_LVARS)"
                            }
                        }
                    }
                }
            },
            {"required", {"address"}}
        },
        ida_mcp::get_microcode
    },
    {
        "optimize_microcode",
        "Optimize microcode to highest maturity level",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}}
                }
            },
            {"required", {"address"}}
        },
        ida_mcp::optimize_microcode
    },
    {
        "print_microcode",
        "Print microcode as text",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}},
                    {"maturity", {{"type", "string"}, {"description", "Maturity level"}}}
                }
            },
            {"required", {"address"}}
        },
        ida_mcp::print_microcode
    },
    {
        "register_hexrays_callback",
        "Register Hex-Rays event callback",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::register_hexrays_callback
    },
    {
        "unregister_hexrays_callback",
        "Unregister Hex-Rays event callback",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::unregister_hexrays_callback
    },
    {
        "get_hexrays_version",
        "Get Hex-Rays decompiler version",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::get_hexrays_version
    },
    {
        "mark_cfunc_dirty",
        "Mark function for re-decompilation",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Function address"}}}
                }
            },
            {"required", {"address"}}
        },
        ida_mcp::mark_cfunc_dirty_tool
    },

    // ===== Advanced Breakpoint Management =====
    {
        "update_bpts",
        "Advanced breakpoint management - add, delete, or enable/disable breakpoints",
        {
            {"type", "object"},
            {
                "properties", {
                    {
                        "operations", {
                            {"type", "array"},
                            {"description", "Array of breakpoint operations"},
                            {
                                "items", {
                                    {"type", "object"},
                                    {
                                        "properties", {
                                            {
                                                "action",
                                                {
                                                    {"type", "string"},
                                                    {"enum", nlohmann::json::array({"add", "delete", "enable"})}
                                                }
                                            },
                                            {"address", {{"type", "integer"}, {"description", "Breakpoint address"}}},
                                            {
                                                "type",
                                                {
                                                    {"type", "string"},
                                                    {
                                                        "enum",
                                                        nlohmann::json::array({"soft", "write", "read", "rdwr", "exec"})
                                                    },
                                                    {"default", "soft"}
                                                }
                                            },
                                            {"enable", {{"type", "boolean"}, {"default", true}}}
                                        }
                                    },
                                    {"required", nlohmann::json::array({"action", "address"})}
                                }
                            }
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"operations"})}
        },
        [](const nlohmann::json &args) -> nlohmann::json {
            if (!args.contains("operations") || !args["operations"].is_array()) {
                throw std::invalid_argument("Missing or invalid 'operations' parameter");
            }

            nlohmann::json results = nlohmann::json::array();
            int success_count = 0;
            int fail_count = 0;

            for (const auto &op: args["operations"]) {
                std::string action = op.value("action", "");
                nlohmann::json result;

                if (action == "add") {
                    bpt_t bpt;
                    bpt.ea = op.value("address", BADADDR);
                    if (bpt.ea == BADADDR) {
                        result["success"] = false;
                        result["error"] = "Add operation missing valid address";
                        results.push_back(result);
                        fail_count++;
                        continue;
                    }

                    std::string type_str = op.value("type", "soft");
                    if (type_str == "soft") {
                        bpt.type = BPT_SOFT;
                    } else if (type_str == "write") {
                        bpt.type = BPT_WRITE;
                    } else if (type_str == "read") {
                        bpt.type = BPT_READ;
                    } else if (type_str == "rdwr") {
                        bpt.type = BPT_RDWR;
                    } else if (type_str == "exec") {
                        bpt.type = BPT_EXEC;
                    } else {
                        result["success"] = false;
                        result["error"] = "Invalid breakpoint type: " + type_str;
                        results.push_back(result);
                        fail_count++;
                        continue;
                    }

                    bpt.size = op.value("size", 0);
                    bpt.pid = op.value("pid", NO_PROCESS);
                    bpt.tid = op.value("tid", NO_THREAD);
                    bpt.pass_count = op.value("pass_count", 0);
                    bpt.flags = BPT_BRK | BPT_ENABLED;

                    bool success = add_bpt(bpt);

                    result["action"] = "add";
                    result["address"] = static_cast<uint64_t>(bpt.ea);
                    result["type"] = type_str;
                    result["success"] = success;

                    if (!success) {
                        result["error"] = "Failed to add breakpoint";
                        fail_count++;
                    } else {
                        success_count++;
                    }
                } else if (action == "delete") {
                    ea_t addr = op.value("address", BADADDR);
                    if (addr == BADADDR) {
                        result["success"] = false;
                        result["error"] = "Delete operation missing valid address";
                        results.push_back(result);
                        fail_count++;
                        continue;
                    }

                    bool success = del_bpt(addr);

                    result["action"] = "delete";
                    result["address"] = static_cast<uint64_t>(addr);
                    result["success"] = success;

                    if (!success) {
                        result["error"] = "Failed to delete breakpoint";
                        fail_count++;
                    } else {
                        success_count++;
                    }
                } else if (action == "enable") {
                    ea_t addr = op.value("address", BADADDR);
                    if (addr == BADADDR) {
                        result["success"] = false;
                        result["error"] = "Enable operation missing valid address";
                        results.push_back(result);
                        fail_count++;
                        continue;
                    }

                    bool enable = op.value("enable", true);
                    bool success = ::enable_bpt(addr, enable);

                    result["action"] = "enable";
                    result["address"] = static_cast<uint64_t>(addr);
                    result["enabled"] = enable;
                    result["success"] = success;

                    if (!success) {
                        result["error"] = std::string("Failed to ") + (enable ? "enable" : "disable") + " breakpoint";
                        fail_count++;
                    } else {
                        success_count++;
                    }
                } else {
                    result["success"] = false;
                    result["error"] = "Invalid action: " + action;
                    results.push_back(result);
                    fail_count++;
                    continue;
                }

                results.push_back(result);
            }

            nlohmann::json summary;
            summary["total_operations"] = results.size();
            summary["successful"] = success_count;
            summary["failed"] = fail_count;
            summary["results"] = results;

            return summary;
        }
    },

    // ===== Instruction Classifiers =====
    {
        "is_call_insn",
        "Check if instruction is a call instruction",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Instruction address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_call_insn_tool
    },
    {
        "is_ret_insn",
        "Check if instruction is a return instruction",
        {
            {"type", "object"},
            {
                "properties", {
                    {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                    {"strict", {{"type", "boolean"}, {"default", true}, {"description", "Strict checking"}}}
                }
            },
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_ret_insn_tool
    },
    {
        "is_indirect_jump_insn",
        "Check if instruction is an indirect jump",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Instruction address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::is_indirect_jump_insn_tool
    },

    // ===== Auto-Analysis Control =====
    {
        "auto_wait",
        "Wait for auto-analysis to complete",
        {{"type", "object"}, {"properties", nlohmann::json::object()}, {"required", nlohmann::json::array()}},
        ida_mcp::auto_wait_tool
    },
    {
        "auto_make_code",
        "Schedule address for code analysis",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Address to analyze as code"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::auto_make_code_tool
    },
    {
        "auto_make_proc",
        "Schedule address for function analysis",
        {
            {"type", "object"},
            {"properties", {{"address", {{"type", "integer"}, {"description", "Function start address"}}}}},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::auto_make_proc_tool
    },
    {
        "plan_and_wait",
        "Plan analysis for address range and wait for completion",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_address", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_address", {{"type", "integer"}, {"description", "End address (optional)"}}},
                    {"final_pass", {{"type", "boolean"}, {"default", true}, {"description", "Perform final analysis pass"}}}
                }
            },
            {"required", nlohmann::json::array({"start_address"})}
        },
        ida_mcp::plan_and_wait_tool
    },
    {
        "auto_wait_range",
        "Wait for auto-analysis to complete for a specific range",
        {
            {"type", "object"},
            {
                "properties", {
                    {"start_address", {{"type", "integer"}, {"description", "Start address"}}},
                    {"end_address", {{"type", "integer"}, {"description", "End address"}}}
                }
            },
            {"required", nlohmann::json::array({"start_address", "end_address"})}
        },
        ida_mcp::auto_wait_range_tool
    },

    // ===== Enum Management =====
    {
        "create_enum",
        "Create a new enumeration type",
        {
            {"type", "object"},
            {
                "properties", {
                    {"name", {{"type", "string"}, {"description", "Enum name"}}},
                    {
                        "base_type",
                        {
                            {"type", "string"},
                            {"enum", nlohmann::json::array({"uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"})},
                            {"default", "uint32"},
                            {"description", "Base integer type"}
                        }
                    }
                }
            },
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::create_enum_tool
    },
    {
        "delete_enum",
        "Delete an enumeration type",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Enum name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::delete_enum_tool
    },
    {
        "add_enum_member",
        "Add a member to an enumeration",
        {
            {"type", "object"},
            {
                "properties", {
                    {"enum_name", {{"type", "string"}, {"description", "Enum name"}}},
                    {"member_name", {{"type", "string"}, {"description", "Member name"}}},
                    {"value", {{"type", "integer"}, {"description", "Member value"}}}
                }
            },
            {"required", nlohmann::json::array({"enum_name", "member_name", "value"})}
        },
        ida_mcp::add_enum_member_tool
    },
    {
        "rename_enum",
        "Rename an enumeration type",
        {
            {"type", "object"},
            {
                "properties", {
                    {"old_name", {{"type", "string"}, {"description", "Current enum name"}}},
                    {"new_name", {{"type", "string"}, {"description", "New enum name"}}}
                }
            },
            {"required", nlohmann::json::array({"old_name", "new_name"})}
        },
        ida_mcp::rename_enum_tool
    },

    // ===== Structure Modification =====
    {
        "create_struct",
        "Create a new structure or union type",
        {
            {"type", "object"},
            {
                "properties", {
                    {"name", {{"type", "string"}, {"description", "Structure name"}}},
                    {"is_union", {{"type", "boolean"}, {"default", false}, {"description", "Create as union instead of struct"}}}
                }
            },
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::create_struct_tool
    },
    {
        "delete_struct",
        "Delete a structure or union type",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Structure name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::delete_struct_tool
    },
    {
        "add_struct_member",
        "Add a member to a structure",
        {
            {"type", "object"},
            {
                "properties", {
                    {"struct_name", {{"type", "string"}, {"description", "Structure name"}}},
                    {"member_name", {{"type", "string"}, {"description", "Member name"}}},
                    {"member_type", {{"type", "string"}, {"description", "Member type (e.g., 'int', 'char *')"}}},
                    {"offset", {{"type", "integer"}, {"description", "Member offset (optional, appends if not specified)"}}}
                }
            },
            {"required", nlohmann::json::array({"struct_name", "member_name", "member_type"})}
        },
        ida_mcp::add_struct_member_tool
    },
    {
        "rename_struct",
        "Rename a structure or union type",
        {
            {"type", "object"},
            {
                "properties", {
                    {"old_name", {{"type", "string"}, {"description", "Current structure name"}}},
                    {"new_name", {{"type", "string"}, {"description", "New structure name"}}}
                }
            },
            {"required", nlohmann::json::array({"old_name", "new_name"})}
        },
        ida_mcp::rename_struct_tool
    },
    {
        "get_struct_size",
        "Get the size of a structure",
        {
            {"type", "object"},
            {"properties", {{"name", {{"type", "string"}, {"description", "Structure name"}}}}},
            {"required", nlohmann::json::array({"name"})}
        },
        ida_mcp::get_struct_size_tool
    },
    // Operand Manipulation Tools
    {
        "op_offset",
        "Convert operand to offset reference",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}},
                {"base", {{"type", "integer"}, {"description", "Base address (optional)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::op_offset_tool
    },
    {
        "op_hex",
        "Convert operand to hexadecimal number",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::op_hex_tool
    },
    {
        "op_dec",
        "Convert operand to decimal number",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::op_dec_tool
    },
    {
        "op_chr",
        "Convert operand to character constant",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::op_chr_tool
    },
    {
        "op_enum",
        "Convert operand to enum member",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}},
                {"enum_name", {{"type", "string"}, {"description", "Enum name"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand", "enum_name"})}
        },
        ida_mcp::op_enum_tool
    },
    {
        "op_stroff",
        "Convert operand to structure offset",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}},
                {"struct_name", {{"type", "string"}, {"description", "Structure name"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand", "struct_name"})}
        },
        ida_mcp::op_stroff_tool
    },
    // Data Definition Tools
    {
        "create_byte",
        "Create byte (8-bit) data at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"size", {{"type", "integer"}, {"description", "Number of bytes (optional, default 1)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::create_byte_tool
    },
    {
        "create_word",
        "Create word (16-bit) data at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"size", {{"type", "integer"}, {"description", "Number of words (optional, default 1)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::create_word_tool
    },
    {
        "create_dword",
        "Create dword (32-bit) data at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"size", {{"type", "integer"}, {"description", "Number of dwords (optional, default 1)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::create_dword_tool
    },
    {
        "create_qword",
        "Create qword (64-bit) data at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"size", {{"type", "integer"}, {"description", "Number of qwords (optional, default 1)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::create_qword_tool
    },
    {
        "create_strlit",
        "Create string literal at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"length", {{"type", "integer"}, {"description", "String length (optional, 0=auto)"}}},
                {"string_type", {{"type", "integer"}, {"description", "String type (STRTYPE_C=0, etc.)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::create_strlit_tool
    },
    // Segment Operations
    {
        "add_segm",
        "Create new segment",
        {
            {"type", "object"},
            {"properties", {
                {"start_address", {{"type", "integer"}, {"description", "Start address"}}},
                {"end_address", {{"type", "integer"}, {"description", "End address"}}},
                {"name", {{"type", "string"}, {"description", "Segment name"}}},
                {"class_name", {{"type", "string"}, {"description", "Segment class (optional, default DATA)"}}}
            }},
            {"required", nlohmann::json::array({"start_address", "end_address", "name"})}
        },
        ida_mcp::add_segm_tool
    },
    {
        "del_segm",
        "Delete segment at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address within segment"}}},
                {"flags", {{"type", "integer"}, {"description", "Deletion flags (optional)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::del_segm_tool
    },
    {
        "set_segm_name",
        "Set segment name",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address within segment"}}},
                {"name", {{"type", "string"}, {"description", "New segment name"}}}
            }},
            {"required", nlohmann::json::array({"address", "name"})}
        },
        ida_mcp::set_segm_name_tool
    },
    {
        "set_segm_class",
        "Set segment class",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address within segment"}}},
                {"class_name", {{"type", "string"}, {"description", "Segment class name"}}}
            }},
            {"required", nlohmann::json::array({"address", "class_name"})}
        },
        ida_mcp::set_segm_class_tool
    },
    {
        "set_segm_addressing",
        "Set segment addressing mode (16/32/64 bit)",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address within segment"}}},
                {"bitness", {{"type", "integer"}, {"description", "Bitness: 0=16bit, 1=32bit, 2=64bit"}}}
            }},
            {"required", nlohmann::json::array({"address", "bitness"})}
        },
        ida_mcp::set_segm_addressing_tool
    },
    // Data Manipulation Tools
    {
        "del_items",
        "Delete data/code at address (make undefined)",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"flags", {{"type", "integer"}, {"description", "Deletion flags (optional)"}}},
                {"size", {{"type", "integer"}, {"description", "Number of bytes (optional, default 1)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::del_items_tool
    },
    {
        "get_item_size",
        "Get item size at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_item_size_tool
    },
    {
        "next_head",
        "Get next item head (next defined item)",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Start address"}}},
                {"max_address", {{"type", "integer"}, {"description", "Maximum address (optional)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::next_head_tool
    },
    {
        "prev_head",
        "Get previous item head",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Start address"}}},
                {"min_address", {{"type", "integer"}, {"description", "Minimum address (optional)"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::prev_head_tool
    },
    {
        "get_flags",
        "Get item flags at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}}
            }},
            {"required", nlohmann::json::array({"address"})}
        },
        ida_mcp::get_flags_tool
    },
    // Offset/Reference Information Tools
    {
        "get_offbase",
        "Get offset base value for operand",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::get_offbase_tool
    },
    {
        "is_off",
        "Check if operand is an offset",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::is_off_tool
    },
    {
        "get_refinfo",
        "Get reference information for operand",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::get_refinfo_tool
    },
    {
        "set_refinfo",
        "Set reference information for operand",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}},
                {"target", {{"type", "integer"}, {"description", "Target address (optional)"}}},
                {"base", {{"type", "integer"}, {"description", "Base address (optional)"}}},
                {"tdelta", {{"type", "integer"}, {"description", "Target delta (optional)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::set_refinfo_tool
    },
    {
        "del_refinfo",
        "Delete reference information for operand",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Instruction address"}}},
                {"operand", {{"type", "integer"}, {"description", "Operand number (0-based)"}}}
            }},
            {"required", nlohmann::json::array({"address", "operand"})}
        },
        ida_mcp::del_refinfo_tool
    },
    // Segment Register Tools
    {
        "get_sreg",
        "Get segment register value at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"register", {{"type", "integer"}, {"description", "Register number"}}}
            }},
            {"required", nlohmann::json::array({"address", "register"})}
        },
        ida_mcp::get_sreg_tool
    },
    {
        "split_sreg_range",
        "Split segment register range at address",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"register", {{"type", "integer"}, {"description", "Register number"}}},
                {"value", {{"type", "integer"}, {"description", "New register value"}}},
                {"tag", {{"type", "integer"}, {"description", "Range tag (optional, default SR_user)"}}}
            }},
            {"required", nlohmann::json::array({"address", "register", "value"})}
        },
        ida_mcp::split_sreg_range_tool
    },
    {
        "get_sreg_range",
        "Get segment register range information",
        {
            {"type", "object"},
            {"properties", {
                {"address", {{"type", "integer"}, {"description", "Address"}}},
                {"register", {{"type", "integer"}, {"description", "Register number"}}}
            }},
            {"required", nlohmann::json::array({"address", "register"})}
        },
        ida_mcp::get_sreg_range_tool
    },
    // Problem/Warning Tools
    {
        "get_problem",
        "Get problem/warning at or after address",
        {
            {"type", "object"},
            {"properties", {
                {"type", {{"type", "integer"}, {"description", "Problem type ID"}}},
                {"low_address", {{"type", "integer"}, {"description", "Start search address (optional, default 0)"}}}
            }},
            {"required", nlohmann::json::array({"type"})}
        },
        ida_mcp::get_problem_tool
    },
    {
        "get_problem_desc",
        "Get problem description at address",
        {
            {"type", "object"},
            {"properties", {
                {"type", {{"type", "integer"}, {"description", "Problem type ID"}}},
                {"address", {{"type", "integer"}, {"description", "Address"}}}
            }},
            {"required", nlohmann::json::array({"type", "address"})}
        },
        ida_mcp::get_problem_desc_tool
    },
    {
        "get_problem_name",
        "Get problem type name",
        {
            {"type", "object"},
            {"properties", {
                {"type", {{"type", "integer"}, {"description", "Problem type ID"}}},
                {"longname", {{"type", "boolean"}, {"description", "Get long name (optional, default true)"}}}
            }},
            {"required", nlohmann::json::array({"type"})}
        },
        ida_mcp::get_problem_name_tool
    },
    {
        "forget_problem",
        "Delete/forget problem at address",
        {
            {"type", "object"},
            {"properties", {
                {"type", {{"type", "integer"}, {"description", "Problem type ID"}}},
                {"address", {{"type", "integer"}, {"description", "Address"}}}
            }},
            {"required", nlohmann::json::array({"type", "address"})}
        },
        ida_mcp::forget_problem_tool
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
