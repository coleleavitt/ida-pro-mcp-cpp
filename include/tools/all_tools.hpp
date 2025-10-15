#pragma once

#include <nlohmann/json.hpp>
#include "common/ida_helpers.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <lines.hpp>
#include <strlist.hpp>
#include <ua.hpp>
#include <hexrays.hpp>

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

// Namespace for all tool implementation functions
namespace ida_mcp {

// ===== Original Tools (converted to function style) =====

inline nlohmann::json get_database_info(const nlohmann::json& args) {
    char buf[QMAXPATH];
    get_input_file_path(buf, sizeof(buf));

    nlohmann::json result;
    result["file_path"] = buf;
    result["func_count"] = get_func_qty();
    result["segment_count"] = get_segm_qty();

    return result;
}

inline nlohmann::json list_functions(const nlohmann::json& args) {
    int limit = args.value("limit", 100);

    nlohmann::json functions = nlohmann::json::array();
    int count = 0;

    for (size_t i = 0; i < get_func_qty() && count < limit; i++) {
        func_t* func = getn_func(i);
        if (func) {
            qstring name;
            get_func_name(&name, func->start_ea);

            nlohmann::json func_info;
            func_info["address"] = static_cast<uint64_t>(func->start_ea);
            func_info["name"] = name.c_str();
            func_info["size"] = static_cast<uint64_t>(func->size());

            functions.push_back(func_info);
            count++;
        }
    }

    nlohmann::json result;
    result["functions"] = functions;
    result["count"] = count;

    return result;
}

inline nlohmann::json get_function_at(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address;
    try {
        address = args["address"];
    } catch (const nlohmann::json::exception& e) {
        throw std::invalid_argument("Invalid address parameter: " + std::string(e.what()));
    }

    if (address == BADADDR) {
        throw std::invalid_argument("Invalid address: BADADDR");
    }

    func_t* func = get_func(address);

    if (!func) {
        throw std::runtime_error("No function found at address 0x" + std::to_string(static_cast<uint64_t>(address)));
    }

    qstring name;
    get_func_name(&name, func->start_ea);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(func->start_ea);
    result["end_address"] = static_cast<uint64_t>(func->end_ea);
    result["name"] = name.c_str();
    result["size"] = static_cast<uint64_t>(func->size());
    result["flags"] = func->flags;

    return result;
}

inline nlohmann::json read_bytes(const nlohmann::json& args) {
    ea_t address = args["address"];
    int size = args["size"];

    if (size > 1024) {
        throw std::runtime_error("Size exceeds maximum of 1024 bytes");
    }

    std::vector<uint8_t> buffer(size);
    if (get_bytes(buffer.data(), size, address) != size) {
        throw std::runtime_error("Failed to read bytes");
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["size"] = size;
    result["bytes"] = buffer;

    return result;
}

// ===== Cross-Reference Tools =====

inline nlohmann::json get_xrefs_to(const nlohmann::json& args) {
    ea_t address = args["address"];
    std::string xref_type = args.value("xref_type", "all");

    nlohmann::json xrefs = nlohmann::json::array();

    xrefblk_t xb;
    for (bool ok = xb.first_to(address, XREF_ALL); ok; ok = xb.next_to()) {
        if (xref_type != "all") {
            bool is_code = xb.iscode;
            if ((xref_type == "code" && !is_code) || (xref_type == "data" && is_code)) {
                continue;
            }
        }

        nlohmann::json xref;
        xref["from"] = static_cast<uint64_t>(xb.from);
        xref["type"] = xb.type;
        xref["is_code"] = xb.iscode;
        xref["user"] = xb.user;

        xrefs.push_back(xref);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["xrefs"] = xrefs;
    result["count"] = xrefs.size();

    return result;
}

inline nlohmann::json get_xrefs_from(const nlohmann::json& args) {
    ea_t address = args["address"];
    std::string xref_type = args.value("xref_type", "all");

    nlohmann::json xrefs = nlohmann::json::array();

    xrefblk_t xb;
    for (bool ok = xb.first_from(address, XREF_ALL); ok; ok = xb.next_from()) {
        if (xref_type != "all") {
            bool is_code = xb.iscode;
            if ((xref_type == "code" && !is_code) || (xref_type == "data" && is_code)) {
                continue;
            }
        }

        nlohmann::json xref;
        xref["to"] = static_cast<uint64_t>(xb.to);
        xref["type"] = xb.type;
        xref["is_code"] = xb.iscode;
        xref["user"] = xb.user;

        xrefs.push_back(xref);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["xrefs"] = xrefs;
    result["count"] = xrefs.size();

    return result;
}

inline nlohmann::json get_callers(const nlohmann::json& args) {
    ea_t address = args["address"];

    nlohmann::json callers = nlohmann::json::array();

    xrefblk_t xb;
    for (bool ok = xb.first_to(address, XREF_ALL); ok; ok = xb.next_to()) {
        if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
            func_t* caller_func = get_func(xb.from);
            if (caller_func) {
                qstring name;
                get_func_name(&name, caller_func->start_ea);

                nlohmann::json caller;
                caller["address"] = static_cast<uint64_t>(caller_func->start_ea);
                caller["call_site"] = static_cast<uint64_t>(xb.from);
                caller["name"] = name.c_str();

                callers.push_back(caller);
            }
        }
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["callers"] = callers;
    result["count"] = callers.size();

    return result;
}

inline nlohmann::json get_callees(const nlohmann::json& args) {
    ea_t address = args["address"];

    nlohmann::json callees = nlohmann::json::array();
    func_t* func = get_func(address);

    if (!func) {
        throw std::runtime_error("No function at address");
    }

    xrefblk_t xb;
    for (ea_t ea = func->start_ea; ea < func->end_ea; ) {
        for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
            if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                func_t* callee_func = get_func(xb.to);
                if (callee_func) {
                    qstring name;
                    get_func_name(&name, callee_func->start_ea);

                    nlohmann::json callee;
                    callee["address"] = static_cast<uint64_t>(callee_func->start_ea);
                    callee["call_site"] = static_cast<uint64_t>(ea);
                    callee["name"] = name.c_str();

                    callees.push_back(callee);
                }
            }
        }
        ea = next_head(ea, func->end_ea);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["callees"] = callees;
    result["count"] = callees.size();

    return result;
}

// ===== Name/Symbol Tools =====

inline nlohmann::json get_name(const nlohmann::json& args) {
    ea_t address = args["address"];
    bool demangled = args.value("demangled", false);

    qstring name;
    if (demangled) {
        get_name(&name, address, GN_DEMANGLED);
    } else {
        get_name(&name, address);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["name"] = name.c_str();
    result["demangled"] = demangled;

    return result;
}

inline nlohmann::json set_name(const nlohmann::json& args) {
    ea_t address = args["address"];
    std::string name = args["name"];

    int flags = 0;
    if (args.value("force", false)) flags |= SN_FORCE;
    if (args.value("public", false)) flags |= SN_PUBLIC;
    if (args.value("weak", false)) flags |= SN_WEAK;
    if (args.value("auto", false)) flags |= SN_AUTO;
    if (args.value("local", false)) flags |= SN_LOCAL;

    bool success = ::set_name(address, name.c_str(), flags);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["name"] = name;
    result["success"] = success;

    return result;
}

inline nlohmann::json get_name_ea(const nlohmann::json& args) {
    std::string name = args["name"];
    ea_t from = args.value("from", 0);

    ea_t address = ::get_name_ea(from, name.c_str());

    nlohmann::json result;
    result["name"] = name;
    result["address"] = static_cast<uint64_t>(address);
    result["found"] = (address != BADADDR);

    return result;
}

// ===== Comment Tools =====

inline nlohmann::json get_comment(const nlohmann::json& args) {
    ea_t address = args["address"];
    bool repeatable = args.value("repeatable", false);

    qstring comment;
    get_cmt(&comment, address, repeatable);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["comment"] = comment.c_str();
    result["repeatable"] = repeatable;

    return result;
}

inline nlohmann::json set_comment(const nlohmann::json& args) {
    ea_t address = args["address"];
    std::string comment = args["comment"];
    bool repeatable = args.value("repeatable", false);
    bool function_comment = args.value("function_comment", false);

    bool success;
    if (function_comment) {
        func_t* func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }
        success = set_func_cmt(func, comment.c_str(), repeatable);
    } else {
        success = set_cmt(address, comment.c_str(), repeatable);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["success"] = success;

    return result;
}

// ===== String Tools =====

inline nlohmann::json get_strings(const nlohmann::json& args) {
    int limit = args.value("limit", 1000);

    build_strlist(); // Ensure string list is up to date

    nlohmann::json strings = nlohmann::json::array();
    size_t count = std::min(static_cast<size_t>(limit), get_strlist_qty());

    for (size_t i = 0; i < count; i++) {
        string_info_t si;
        if (get_strlist_item(&si, i)) {
            qstring str;
            if (get_strlit_contents(&str, si.ea, si.length, si.type)) {
                nlohmann::json string_obj;
                string_obj["address"] = static_cast<uint64_t>(si.ea);
                string_obj["length"] = si.length;
                string_obj["type"] = si.type;
                string_obj["content"] = str.c_str();

                strings.push_back(string_obj);
            }
        }
    }

    nlohmann::json result;
    result["strings"] = strings;
    result["count"] = strings.size();
    result["total"] = get_strlist_qty();

    return result;
}

inline nlohmann::json get_string_at(const nlohmann::json& args) {
    ea_t address = args["address"];

    opinfo_t oi;
    flags64_t flags = get_flags(address);

    if (!is_strlit(flags)) {
        throw std::runtime_error("No string at address");
    }

    qstring str;
    int32 len = get_max_strlit_length(address, STRTYPE_C, ALOPT_IGNHEADS);
    if (len > 0) {
        get_strlit_contents(&str, address, len, STRTYPE_C);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["content"] = str.c_str();
    result["length"] = len;

    return result;
}

// ===== Segment Tools =====

inline nlohmann::json get_segments(const nlohmann::json& args) {
    nlohmann::json segments = nlohmann::json::array();

    for (int i = 0; i < get_segm_qty(); i++) {
        segment_t* seg = getnseg(i);
        if (seg) {
            qstring name;
            get_segm_name(&name, seg);

            nlohmann::json seg_info;
            seg_info["name"] = name.c_str();
            seg_info["start_ea"] = static_cast<uint64_t>(seg->start_ea);
            seg_info["end_ea"] = static_cast<uint64_t>(seg->end_ea);
            seg_info["size"] = static_cast<uint64_t>(seg->size());
            seg_info["bitness"] = seg->bitness;
            seg_info["type"] = seg->type;
            seg_info["perm"] = seg->perm;

            segments.push_back(seg_info);
        }
    }

    nlohmann::json result;
    result["segments"] = segments;
    result["count"] = segments.size();

    return result;
}

inline nlohmann::json get_segment_at(const nlohmann::json& args) {
    ea_t address = args["address"];

    segment_t* seg = getseg(address);
    if (!seg) {
        throw std::runtime_error("No segment at address");
    }

    qstring name, sclass;
    get_segm_name(&name, seg);
    get_segm_class(&sclass, seg);

    nlohmann::json result;
    result["name"] = name.c_str();
    result["class"] = sclass.c_str();
    result["start_ea"] = static_cast<uint64_t>(seg->start_ea);
    result["end_ea"] = static_cast<uint64_t>(seg->end_ea);
    result["size"] = static_cast<uint64_t>(seg->size());
    result["bitness"] = seg->bitness;
    result["type"] = seg->type;
    result["perm"] = seg->perm;
    result["align"] = seg->align;

    return result;
}

// ===== Instruction Analysis Tools =====

inline nlohmann::json decode_insn(const nlohmann::json& args) {
    ea_t address = args["address"];

    insn_t insn;
    int len = decode_insn(&insn, address);

    if (len == 0) {
        throw std::runtime_error("Failed to decode instruction");
    }

    qstring mnem;
    print_insn_mnem(&mnem, address);

    nlohmann::json operands = nlohmann::json::array();
    for (int i = 0; i < UA_MAXOP && insn.ops[i].type != o_void; i++) {
        qstring opnd_str;
        print_operand(&opnd_str, address, i);

        nlohmann::json opnd;
        opnd["index"] = i;
        opnd["type"] = insn.ops[i].type;
        opnd["text"] = opnd_str.c_str();

        if (insn.ops[i].type == o_reg) {
            opnd["reg"] = insn.ops[i].reg;
        } else if (insn.ops[i].type == o_imm) {
            opnd["value"] = static_cast<uint64_t>(insn.ops[i].value);
        } else if (insn.ops[i].type == o_mem || insn.ops[i].type == o_near || insn.ops[i].type == o_far) {
            opnd["addr"] = static_cast<uint64_t>(insn.ops[i].addr);
        }

        operands.push_back(opnd);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["mnemonic"] = mnem.c_str();
    result["size"] = len;
    result["operands"] = operands;

    return result;
}

inline nlohmann::json get_disasm_line(const nlohmann::json& args) {
    ea_t address = args["address"];
    int flags = args.value("flags", 0);

    qstring line;
    generate_disasm_line(&line, address, flags);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(address);
    result["line"] = line.c_str();

    return result;
}

inline nlohmann::json generate_disasm_text(const nlohmann::json& args) {
    ea_t start_address = args["start_address"];
    ea_t end_address = args.value("end_address", start_address + 0x100);
    int max_lines = args.value("max_lines", 50);
    int flags = args.value("flags", 0);

    nlohmann::json lines = nlohmann::json::array();
    int count = 0;

    ea_t ea = start_address;
    while (ea < end_address && count < max_lines) {
        qstring line;
        generate_disasm_line(&line, ea, flags);

        nlohmann::json line_obj;
        line_obj["address"] = static_cast<uint64_t>(ea);
        line_obj["text"] = line.c_str();

        lines.push_back(line_obj);

        ea = next_head(ea, end_address);
        if (ea == BADADDR) break;
        count++;
    }

    nlohmann::json result;
    result["start_address"] = static_cast<uint64_t>(start_address);
    result["lines"] = lines;
    result["count"] = count;

    return result;
}

// ===== Function Tools =====

inline nlohmann::json get_func_name(const nlohmann::json& args) {
    ea_t address = args["address"];
    bool demangled = args.value("demangled", false);

    func_t* func = get_func(address);
    if (!func) {
        throw std::runtime_error("No function at address");
    }

    qstring name;
    ::get_func_name(&name, func->start_ea);

    if (demangled) {
        qstring demangled_name;
        if (::get_name(&demangled_name, func->start_ea, GN_DEMANGLED) > 0) {
            name = demangled_name;
        }
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(func->start_ea);
    result["name"] = name.c_str();
    result["demangled"] = demangled;

    return result;
}

inline nlohmann::json get_func_comment(const nlohmann::json& args) {
    ea_t address = args["address"];
    bool repeatable = args.value("repeatable", false);

    func_t* func = get_func(address);
    if (!func) {
        throw std::runtime_error("No function at address");
    }

    qstring comment;
    get_func_cmt(&comment, func, repeatable);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(func->start_ea);
    result["comment"] = comment.c_str();
    result["repeatable"] = repeatable;

    return result;
}

inline nlohmann::json get_func_size(const nlohmann::json& args) {
    ea_t address = args["address"];

    func_t* func = get_func(address);
    if (!func) {
        throw std::runtime_error("No function at address");
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(func->start_ea);
    result["size"] = static_cast<uint64_t>(func->size());

    return result;
}

inline nlohmann::json get_func_ranges(const nlohmann::json& args) {
    ea_t address = args["address"];

    func_t* func = get_func(address);
    if (!func) {
        throw std::runtime_error("No function at address");
    }

    nlohmann::json ranges = nlohmann::json::array();

    // Main function range
    nlohmann::json main_range;
    main_range["start_ea"] = static_cast<uint64_t>(func->start_ea);
    main_range["end_ea"] = static_cast<uint64_t>(func->end_ea);
    main_range["type"] = "main";
    ranges.push_back(main_range);

    // Function tails
    func_tail_iterator_t fti(func);
    for (bool ok = fti.first(); ok; ok = fti.next()) {
        const range_t& tail = fti.chunk();
        nlohmann::json tail_range;
        tail_range["start_ea"] = static_cast<uint64_t>(tail.start_ea);
        tail_range["end_ea"] = static_cast<uint64_t>(tail.end_ea);
        tail_range["type"] = "tail";
        ranges.push_back(tail_range);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(func->start_ea);
    result["ranges"] = ranges;
    result["count"] = ranges.size();

    return result;
}

// ===== Decompilation Tools (Hex-Rays) =====

inline nlohmann::json decompile_function(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address = args["address"];
    int flags = args.value("flags", 0);

    // Get function at address
    func_t* pfn = get_func(address);
    if (!pfn) {
        throw std::runtime_error("No function found at address 0x" + std::to_string(static_cast<uint64_t>(address)));
    }

    // Check if decompiler is available
    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available or failed to initialize");
    }

    // Decompile the function
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, flags);

    if (!cfunc) {
        std::string error_msg = "Decompilation failed";
        if (hf.str.length() > 0) {
            error_msg += ": " + std::string(hf.str.c_str());
        }
        error_msg += " (error code: " + std::to_string(hf.code) + ")";
        throw std::runtime_error(error_msg);
    }

    // Get pseudocode as string
    qstring pseudocode;
    cfunc->get_pseudocode();

    // Build the pseudocode text
    qstring func_text;

    // Print function prototype
    cfunc->print_dcl(&func_text);
    func_text.append("\n");

    // Print function body using strvec
    const strvec_t& sv = cfunc->get_pseudocode();
    for (size_t i = 0; i < sv.size(); i++) {
        func_text.append(sv[i].line.c_str());
        func_text.append("\n");
    }

    // Get local variables
    nlohmann::json lvars = nlohmann::json::array();
    lvars_t* vars = cfunc->get_lvars();
    if (vars) {
        for (size_t i = 0; i < vars->size(); i++) {
            const lvar_t& var = (*vars)[i];

            qstring var_type_str;
            var.type().print(&var_type_str);

            nlohmann::json lvar;
            lvar["name"] = var.name.c_str();
            lvar["type"] = var_type_str.c_str();
            lvar["width"] = var.width;
            lvar["is_arg"] = var.is_arg_var();
            lvar["is_result"] = var.is_result_var();

            lvars.push_back(lvar);
        }
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(pfn->start_ea);
    result["pseudocode"] = func_text.c_str();
    result["maturity"] = cfunc->maturity;
    result["lvars"] = lvars;

    return result;
}

inline nlohmann::json decompile_snippet(const nlohmann::json& args) {
    if (!args.contains("start_address")) {
        throw std::invalid_argument("Missing required parameter: start_address");
    }

    ea_t start_ea = args["start_address"];
    ea_t end_ea = args.value("end_address", start_ea + 0x100);
    int flags = args.value("flags", 0);

    // Check if decompiler is available
    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available or failed to initialize");
    }

    // Create range
    rangevec_t ranges;
    ranges.push_back(range_t(start_ea, end_ea));

    // Decompile the snippet
    hexrays_failure_t hf;
    cfuncptr_t cfunc = ::decompile_snippet(ranges, &hf, flags);

    if (!cfunc) {
        std::string error_msg = "Decompilation failed";
        if (hf.str.length() > 0) {
            error_msg += ": " + std::string(hf.str.c_str());
        }
        throw std::runtime_error(error_msg);
    }

    // Get pseudocode
    qstring func_text;
    cfunc->print_dcl(&func_text);
    func_text.append("\n");

    const strvec_t& sv = cfunc->get_pseudocode();
    for (size_t i = 0; i < sv.size(); i++) {
        func_text.append(sv[i].line.c_str());
        func_text.append("\n");
    }

    nlohmann::json result;
    result["start_address"] = static_cast<uint64_t>(start_ea);
    result["end_address"] = static_cast<uint64_t>(end_ea);
    result["pseudocode"] = func_text.c_str();

    return result;
}

inline nlohmann::json generate_microcode(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address = args["address"];
    std::string maturity_str = args.value("maturity", "MMAT_GLBOPT");

    // Get function
    func_t* pfn = get_func(address);
    if (!pfn) {
        throw std::runtime_error("No function found at address");
    }

    // Check if decompiler is available
    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available");
    }

    // Map maturity string to enum
    mba_maturity_t maturity = MMAT_GLBOPT3;
    if (maturity_str == "MMAT_GENERATED") maturity = MMAT_GENERATED;
    else if (maturity_str == "MMAT_PREOPTIMIZED") maturity = MMAT_PREOPTIMIZED;
    else if (maturity_str == "MMAT_LOCOPT") maturity = MMAT_LOCOPT;
    else if (maturity_str == "MMAT_CALLS") maturity = MMAT_CALLS;
    else if (maturity_str == "MMAT_GLBOPT1") maturity = MMAT_GLBOPT1;
    else if (maturity_str == "MMAT_GLBOPT2") maturity = MMAT_GLBOPT2;
    else if (maturity_str == "MMAT_GLBOPT3") maturity = MMAT_GLBOPT3;

    // Generate microcode
    mba_ranges_t mbr(pfn);
    hexrays_failure_t hf;
    mba_t* mba = ::gen_microcode(mbr, &hf, nullptr, 0, maturity);

    if (!mba) {
        std::string error_msg = "Microcode generation failed";
        if (hf.str.length() > 0) {
            error_msg += ": " + std::string(hf.str.c_str());
        }
        throw std::runtime_error(error_msg);
    }

    // Build microcode text using vd_printer_t
    qstring microcode_text;
    class qstring_mba_printer_t : public vd_printer_t {
        qstring &s;
    public:
        qstring_mba_printer_t(qstring &_s) : s(_s) {}
        AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...) override {
            va_list va;
            va_start(va, format);
            for (int i = 0; i < indent; i++)
                s.append(' ');
            s.cat_vsprnt(format, va);
            va_end(va);
            return s.length();
        }
    };
    qstring_mba_printer_t qp(microcode_text);
    mba->print(qp);

    // Get basic blocks info
    nlohmann::json blocks = nlohmann::json::array();
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);

        nlohmann::json block;
        block["serial"] = blk->serial;
        block["start"] = static_cast<uint64_t>(blk->start);
        block["end"] = static_cast<uint64_t>(blk->end);
        block["type"] = blk->type;
        block["npred"] = blk->npred();
        block["nsucc"] = blk->nsucc();

        // Get instruction count
        int insn_count = 0;
        for (minsn_t* ins = blk->head; ins != nullptr; ins = ins->next) {
            insn_count++;
        }
        block["insn_count"] = insn_count;

        blocks.push_back(block);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(pfn->start_ea);
    result["maturity"] = mba->maturity;
    result["maturity_name"] = maturity_str;
    result["microcode"] = microcode_text.c_str();
    result["blocks"] = blocks;
    result["block_count"] = mba->qty;

    delete mba;
    return result;
}

inline nlohmann::json get_local_variables(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address = args["address"];

    func_t* pfn = get_func(address);
    if (!pfn) {
        throw std::runtime_error("No function found at address");
    }

    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available");
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);

    if (!cfunc) {
        throw std::runtime_error("Failed to decompile function");
    }

    nlohmann::json lvars = nlohmann::json::array();
    lvars_t* vars = cfunc->get_lvars();

    if (vars) {
        for (size_t i = 0; i < vars->size(); i++) {
            const lvar_t& var = (*vars)[i];

            qstring var_type_str;
            var.type().print(&var_type_str);

            nlohmann::json lvar;
            lvar["index"] = i;
            lvar["name"] = var.name.c_str();
            lvar["type"] = var_type_str.c_str();
            lvar["width"] = var.width;
            lvar["is_arg"] = var.is_arg_var();
            lvar["is_result"] = var.is_result_var();
            lvar["used"] = var.used();
            lvar["is_promoted_arg"] = var.is_promoted_arg();

            // Get comments if any
            if (!var.cmt.empty()) {
                lvar["comment"] = var.cmt.c_str();
            }

            lvars.push_back(lvar);
        }
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(pfn->start_ea);
    result["lvars"] = lvars;
    result["count"] = lvars.size();

    return result;
}

inline nlohmann::json get_ctree(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address = args["address"];

    func_t* pfn = get_func(address);
    if (!pfn) {
        throw std::runtime_error("No function found at address");
    }

    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available");
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);

    if (!cfunc) {
        throw std::runtime_error("Failed to decompile function");
    }

    // Print the ctree structure
    qstring tree_text;
    cfunc->body.print1(&tree_text, &*cfunc);

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(pfn->start_ea);
    result["ctree"] = tree_text.c_str();

    return result;
}

inline nlohmann::json print_microcode_block(const nlohmann::json& args) {
    if (!args.contains("address")) {
        throw std::invalid_argument("Missing required parameter: address");
    }

    ea_t address = args["address"];
    int block_serial = args.value("block_serial", 0);

    func_t* pfn = get_func(address);
    if (!pfn) {
        throw std::runtime_error("No function found at address");
    }

    if (!init_hexrays_plugin()) {
        throw std::runtime_error("Hex-Rays decompiler not available");
    }

    mba_ranges_t mbr(pfn);
    hexrays_failure_t hf;
    mba_t* mba = ::gen_microcode(mbr, &hf, nullptr, 0, MMAT_GLBOPT3);

    if (!mba) {
        throw std::runtime_error("Microcode generation failed");
    }

    if (block_serial >= mba->qty) {
        delete mba;
        throw std::runtime_error("Block serial out of range");
    }

    mblock_t* blk = mba->get_mblock(block_serial);

    // Print all instructions in the block
    nlohmann::json instructions = nlohmann::json::array();
    for (minsn_t* ins = blk->head; ins != nullptr; ins = ins->next) {
        qstring insn_str;
        ins->print(&insn_str);

        nlohmann::json insn;
        insn["ea"] = static_cast<uint64_t>(ins->ea);
        insn["opcode"] = ins->opcode;
        insn["text"] = insn_str.c_str();

        instructions.push_back(insn);
    }

    nlohmann::json result;
    result["address"] = static_cast<uint64_t>(pfn->start_ea);
    result["block_serial"] = block_serial;
    result["start"] = static_cast<uint64_t>(blk->start);
    result["end"] = static_cast<uint64_t>(blk->end);
    result["instructions"] = instructions;
    result["insn_count"] = instructions.size();

    delete mba;
    return result;
}

} // namespace ida_mcp
