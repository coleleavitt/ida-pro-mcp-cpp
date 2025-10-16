#pragma once

#include <nlohmann/json.hpp>
#include "../common/ida_helpers.hpp"

#include <regex>
#include <cstdlib>
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
#include <typeinf.hpp>
#include <srclang.hpp>
#include <gdl.hpp>
#include <frame.hpp>
#include <demangle.hpp>
#include <nalt.hpp>
#include <entry.hpp>
#include <search.hpp>
#include <fixup.hpp>
#include <jumptable.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <auto.hpp>

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
#include <expr.hpp>

// Namespace for all tool implementation functions
namespace ida_mcp {
    // ===== Original Tools (converted to function style) =====

    inline nlohmann::json get_database_info(const nlohmann::json &args) {
        char buf[QMAXPATH];
        get_input_file_path(buf, sizeof(buf));

        nlohmann::json result;
        result["file_path"] = buf;
        result["func_count"] = get_func_qty();
        result["segment_count"] = get_segm_qty();

        return result;
    }

    inline nlohmann::json list_functions(const nlohmann::json &args) {
        int limit = args.value("limit", 100);

        nlohmann::json functions = nlohmann::json::array();
        int count = 0;

        for (size_t i = 0; i < get_func_qty() && count < limit; i++) {
            func_t *func = getn_func(i);
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

    inline nlohmann::json get_function_at(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address;
        try {
            address = args["address"];
        } catch (const nlohmann::json::exception &e) {
            throw std::invalid_argument("Invalid address parameter: " + std::string(e.what()));
        }

        if (address == BADADDR) {
            throw std::invalid_argument("Invalid address: BADADDR");
        }

        func_t *func = get_func(address);

        if (!func) {
            throw std::runtime_error(
                "No function found at address 0x" + std::to_string(static_cast<uint64_t>(address)));
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

    inline nlohmann::json read_bytes(const nlohmann::json &args) {
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

    inline nlohmann::json get_xrefs_to(const nlohmann::json &args) {
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

    inline nlohmann::json get_xrefs_from(const nlohmann::json &args) {
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

    inline nlohmann::json get_callers(const nlohmann::json &args) {
        ea_t address = args["address"];

        nlohmann::json callers = nlohmann::json::array();

        xrefblk_t xb;
        for (bool ok = xb.first_to(address, XREF_ALL); ok; ok = xb.next_to()) {
            if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                func_t *caller_func = get_func(xb.from);
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

    inline nlohmann::json get_callees(const nlohmann::json &args) {
        ea_t address = args["address"];

        nlohmann::json callees = nlohmann::json::array();
        func_t *func = get_func(address);

        if (!func) {
            throw std::runtime_error("No function at address");
        }

        xrefblk_t xb;
        for (ea_t ea = func->start_ea; ea < func->end_ea;) {
            for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                    func_t *callee_func = get_func(xb.to);
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

    inline nlohmann::json get_name(const nlohmann::json &args) {
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

    inline nlohmann::json set_name(const nlohmann::json &args) {
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

    inline nlohmann::json get_name_ea(const nlohmann::json &args) {
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

    inline nlohmann::json get_comment(const nlohmann::json &args) {
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

    inline nlohmann::json set_comment(const nlohmann::json &args) {
        ea_t address = args["address"];
        std::string comment = args["comment"];
        bool repeatable = args.value("repeatable", false);
        bool function_comment = args.value("function_comment", false);

        bool success;
        if (function_comment) {
            func_t *func = get_func(address);
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

    inline nlohmann::json get_strings(const nlohmann::json &args) {
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

    inline nlohmann::json get_string_at(const nlohmann::json &args) {
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

    inline nlohmann::json get_segments(const nlohmann::json &args) {
        nlohmann::json segments = nlohmann::json::array();

        for (int i = 0; i < get_segm_qty(); i++) {
            segment_t *seg = getnseg(i);
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

    inline nlohmann::json get_segment_at(const nlohmann::json &args) {
        ea_t address = args["address"];

        segment_t *seg = getseg(address);
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

    inline nlohmann::json decode_insn(const nlohmann::json &args) {
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

    inline nlohmann::json get_disasm_line(const nlohmann::json &args) {
        ea_t address = args["address"];
        int flags = args.value("flags", 0);

        qstring line;
        generate_disasm_line(&line, address, flags);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["line"] = line.c_str();

        return result;
    }

    inline nlohmann::json generate_disasm_text(const nlohmann::json &args) {
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

    inline nlohmann::json get_func_name(const nlohmann::json &args) {
        ea_t address = args["address"];
        bool demangled = args.value("demangled", false);

        func_t *func = get_func(address);
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

    inline nlohmann::json get_func_comment(const nlohmann::json &args) {
        ea_t address = args["address"];
        bool repeatable = args.value("repeatable", false);

        func_t *func = get_func(address);
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

    inline nlohmann::json get_func_size(const nlohmann::json &args) {
        ea_t address = args["address"];

        func_t *func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(func->start_ea);
        result["size"] = static_cast<uint64_t>(func->size());

        return result;
    }

    inline nlohmann::json get_func_ranges(const nlohmann::json &args) {
        ea_t address = args["address"];

        func_t *func = get_func(address);
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
            const range_t &tail = fti.chunk();
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

    inline nlohmann::json decompile_function(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int flags = args.value("flags", 0);

        // Get function at address
        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error(
                "No function found at address 0x" + std::to_string(static_cast<uint64_t>(address)));
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

        // Get pseudocode as lines
        const strvec_t &sv = cfunc->get_pseudocode();

        // Build pseudocode string
        qstring pseudocode;
        for (size_t i = 0; i < sv.size(); i++) {
            pseudocode.append(sv[i].line.c_str());
            pseudocode.append("\n");
        }

        // Remove markup tags
        tag_remove(&pseudocode, 0);

        // Get local variables
        nlohmann::json lvars = nlohmann::json::array();
        lvars_t *vars = cfunc->get_lvars();
        if (vars) {
            for (size_t i = 0; i < vars->size(); i++) {
                const lvar_t &var = (*vars)[i];

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
        result["pseudocode"] = pseudocode.c_str();
        result["maturity"] = cfunc->maturity;
        result["lvars"] = lvars;

        return result;
    }

    inline nlohmann::json search_decompiled(const nlohmann::json &args) {
        if (!args.contains("pattern")) {
            throw std::invalid_argument("Missing required parameter: pattern");
        }

        std::string pattern_str = args["pattern"].get<std::string>();
        std::regex pattern(pattern_str);
        size_t limit = args.value("limit", static_cast<size_t>(100));

        // Check if decompiler is available
        if (!init_hexrays_plugin()) {
            throw std::runtime_error("Hex-Rays decompiler not available or failed to initialize");
        }

        nlohmann::json result = nlohmann::json::array();

        // Iterate over all functions
        size_t func_count = get_func_qty();
        size_t found = 0;
        for (size_t i = 0; i < func_count && found < limit; i++) {
            func_t *pfn = getn_func(i);
            if (!pfn) continue;

            // Decompile the function
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile_func(pfn, &hf, 0);

            if (!cfunc) continue;

            // Get pseudocode
            const strvec_t &sv = cfunc->get_pseudocode();
            qstring pseudocode;
            for (size_t j = 0; j < sv.size(); j++) {
                pseudocode.append(sv[j].line.c_str());
                pseudocode.append("\n");
            }

            // Remove markup
            tag_remove(&pseudocode, 0);

            std::string text = pseudocode.c_str();

            // Check for regex match
            if (std::regex_search(text, pattern)) {
                nlohmann::json func_info;
                func_info["address"] = static_cast<uint64_t>(pfn->start_ea);
                qstring func_name;
                get_func_name(&func_name, pfn->start_ea);
                func_info["name"] = func_name.c_str();
                result.push_back(func_info);
                found++;
            }
        }

        return result;
    }

    inline nlohmann::json search_disasm(const nlohmann::json &args) {
        if (!args.contains("pattern")) {
            throw std::invalid_argument("Missing required parameter: pattern");
        }

        std::string pattern_str = args["pattern"].get<std::string>();
        std::regex pattern(pattern_str);
        size_t limit = args.value("limit", static_cast<size_t>(100));

        nlohmann::json result = nlohmann::json::array();

        // Iterate over all functions
        size_t func_count = get_func_qty();
        size_t found = 0;
        for (size_t i = 0; i < func_count && found < limit; i++) {
            func_t *pfn = getn_func(i);
            if (!pfn) continue;

            // Get disassembly text
            text_t disasm;
            gen_disasm_text(disasm, pfn->start_ea, pfn->end_ea, false);

            std::string text;
            for (const auto &tw: disasm) {
                text += tw.line.c_str();
                text += "\n";
            }

            // Check for regex match
            if (std::regex_search(text, pattern)) {
                nlohmann::json func_info;
                func_info["address"] = static_cast<uint64_t>(pfn->start_ea);
                qstring func_name;
                get_func_name(&func_name, pfn->start_ea);
                func_info["name"] = func_name.c_str();
                result.push_back(func_info);
                found++;
            }
        }

        return result;
    }

    // ===== iOS-Specific Tools =====

    inline nlohmann::json get_objc_classes(const nlohmann::json &args) {
        nlohmann::json result = nlohmann::json::array();

        // Scan for Objective-C class references in strings
        size_t str_count = get_strlist_qty();
        for (size_t i = 0; i < str_count; i++) {
            string_info_t si;
            if (get_strlist_item(&si, i)) {
                qstring str;
                if (get_strlit_contents(&str, si.ea, si.length, si.type)) {
                    std::string str_val = str.c_str();
                    // Look for class name patterns (basic heuristic)
                    if (str_val.length() > 2 && str_val[0] >= 'A' && str_val[0] <= 'Z') {
                        nlohmann::json class_info;
                        class_info["name"] = str_val;
                        class_info["address"] = static_cast<uint64_t>(si.ea);
                        result.push_back(class_info);
                    }
                }
            }
        }

        return result;
    }

    inline nlohmann::json get_objc_selectors(const nlohmann::json &args) {
        nlohmann::json result = nlohmann::json::array();

        // Scan for selector strings (end with ':')
        size_t str_count = get_strlist_qty();
        for (size_t i = 0; i < str_count; i++) {
            string_info_t si;
            if (get_strlist_item(&si, i)) {
                qstring str;
                if (get_strlit_contents(&str, si.ea, si.length, si.type)) {
                    std::string str_val = str.c_str();
                    // Look for selector patterns (contain ':' and start with lowercase)
                    if (str_val.find(':') != std::string::npos &&
                        str_val.length() > 1 && str_val[0] >= 'a' && str_val[0] <= 'z') {
                        nlohmann::json selector;
                        selector["name"] = str_val;
                        selector["address"] = static_cast<uint64_t>(si.ea);
                        result.push_back(selector);
                    }
                }
            }
        }

        return result;
    }

    inline nlohmann::json get_entitlements(const nlohmann::json &args) {
        nlohmann::json result;

        // Find __TEXT,__entitlements section
        size_t seg_count = get_segm_qty();
        for (size_t i = 0; i < seg_count; i++) {
            segment_t *seg = getnseg(i);
            if (!seg) continue;

            qstring seg_name;
            get_segm_name(&seg_name, seg);

            if (strcmp(seg_name.c_str(), "__entitlements") == 0 ||
                strstr(seg_name.c_str(), "entitlements") != nullptr) {
                // Read the entitlements data
                size_t size = seg->end_ea - seg->start_ea;
                std::vector<uint8_t> data(size);
                if (get_bytes(data.data(), size, seg->start_ea)) {
                    std::string entitlements_str(data.begin(), data.end());
                    result["entitlements"] = entitlements_str;
                    result["address"] = static_cast<uint64_t>(seg->start_ea);
                    result["size"] = size;
                }
                break;
            }
        }

        if (result.empty()) {
            result["error"] = "No entitlements section found";
        }

        return result;
    }

    inline nlohmann::json get_codesignature(const nlohmann::json &args) {
        nlohmann::json result;

        // Find code signature section
        size_t seg_count = get_segm_qty();
        for (size_t i = 0; i < seg_count; i++) {
            segment_t *seg = getnseg(i);
            if (!seg) continue;

            qstring seg_name;
            get_segm_name(&seg_name, seg);

            if (strstr(seg_name.c_str(), "__LINKEDIT") != nullptr ||
                strstr(seg_name.c_str(), "signature") != nullptr) {
                result["segment"] = seg_name.c_str();
                result["start"] = static_cast<uint64_t>(seg->start_ea);
                result["end"] = static_cast<uint64_t>(seg->end_ea);
                result["size"] = seg->end_ea - seg->start_ea;
                break;
            }
        }

        if (result.empty()) {
            result["error"] = "No code signature section found";
        }

        return result;
    }


    inline nlohmann::json demangle_swift_symbols(const nlohmann::json &args) {
        if (!args.contains("mangled_name")) {
            throw std::invalid_argument("Missing required parameter: mangled_name");
        }

        std::string mangled = args["mangled_name"].get<std::string>();
        qstring demangled;

        if (demangle_name(&demangled, mangled.c_str(), 0)) {
            nlohmann::json result;
            result["demangled"] = demangled.c_str();
            result["original"] = mangled;
            return result;
        } else {
            nlohmann::json result;
            result["demangled"] = mangled; // fallback to original
            result["original"] = mangled;
            return result;
        }
    }

    inline nlohmann::json get_macho_header(const nlohmann::json &args) {
        nlohmann::json result;

        // Basic file info - for Mach-O files, IDA provides segment info
        result["file_type"] = "unknown"; // Would need macho.hpp for proper detection

        // Get segments as proxy for Mach-O info
        nlohmann::json segments = nlohmann::json::array();
        size_t seg_count = get_segm_qty();
        for (size_t i = 0; i < seg_count; i++) {
            segment_t *seg = getnseg(i);
            if (!seg) continue;

            qstring seg_name;
            get_segm_name(&seg_name, seg);

            nlohmann::json seg_info;
            seg_info["name"] = seg_name.c_str();
            seg_info["start"] = static_cast<uint64_t>(seg->start_ea);
            seg_info["end"] = static_cast<uint64_t>(seg->end_ea);
            seg_info["permissions"] = seg->perm;
            segments.push_back(seg_info);
        }
        result["segments"] = segments;

        return result;
    }

    inline nlohmann::json get_framework_info(const nlohmann::json &args) {
        nlohmann::json result = nlohmann::json::array();

        // Scan for framework references in segment names
        size_t seg_count = get_segm_qty();
        for (size_t i = 0; i < seg_count; i++) {
            segment_t *seg = getnseg(i);
            if (!seg) continue;

            qstring seg_name;
            get_segm_name(&seg_name, seg);

            std::string name_str = seg_name.c_str();
            if (name_str.find(".framework") != std::string::npos ||
                name_str.find("Frameworks") != std::string::npos) {
                nlohmann::json framework;
                framework["segment"] = name_str;
                framework["start"] = static_cast<uint64_t>(seg->start_ea);
                framework["end"] = static_cast<uint64_t>(seg->end_ea);
                result.push_back(framework);
            }
        }

        return result;
    }

    inline nlohmann::json decompile_snippet(const nlohmann::json &args) {
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

        const strvec_t &sv = cfunc->get_pseudocode();
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

    inline nlohmann::json generate_microcode(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        std::string maturity_str = args.value("maturity", "MMAT_GLBOPT");

        // Get function
        func_t *pfn = get_func(address);
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
        mba_t *mba = ::gen_microcode(mbr, &hf, nullptr, 0, maturity);

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
            qstring_mba_printer_t(qstring &_s) : s(_s) {
            }

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
            mblock_t *blk = mba->get_mblock(i);

            nlohmann::json block;
            block["serial"] = blk->serial;
            block["start"] = static_cast<uint64_t>(blk->start);
            block["end"] = static_cast<uint64_t>(blk->end);
            block["type"] = blk->type;
            block["npred"] = blk->npred();
            block["nsucc"] = blk->nsucc();

            // Get instruction count
            int insn_count = 0;
            for (minsn_t *ins = blk->head; ins != nullptr; ins = ins->next) {
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

    inline nlohmann::json get_local_variables(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
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
        lvars_t *vars = cfunc->get_lvars();

        if (vars) {
            for (size_t i = 0; i < vars->size(); i++) {
                const lvar_t &var = (*vars)[i];

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

    inline nlohmann::json get_ctree(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
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

    inline nlohmann::json print_microcode_block(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int block_serial = args.value("block_serial", 0);

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function found at address");
        }

        if (!init_hexrays_plugin()) {
            throw std::runtime_error("Hex-Rays decompiler not available");
        }

        mba_ranges_t mbr(pfn);
        hexrays_failure_t hf;
        mba_t *mba = ::gen_microcode(mbr, &hf, nullptr, 0, MMAT_GLBOPT3);

        if (!mba) {
            throw std::runtime_error("Microcode generation failed");
        }

        if (block_serial >= mba->qty) {
            delete mba;
            throw std::runtime_error("Block serial out of range");
        }

        mblock_t *blk = mba->get_mblock(block_serial);

        // Print all instructions in the block
        nlohmann::json instructions = nlohmann::json::array();
        for (minsn_t *ins = blk->head; ins != nullptr; ins = ins->next) {
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

    // ===== Type System Tools =====

    inline nlohmann::json get_type(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tinfo_t tif;
        if (!get_tinfo(&tif, address)) {
            throw std::runtime_error("No type information at address");
        }

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["type"] = type_str.c_str();
        result["size"] = tif.get_size();
        result["is_ptr"] = tif.is_ptr();
        result["is_func"] = tif.is_func();
        result["is_array"] = tif.is_array();
        result["is_struct"] = tif.is_struct();
        result["is_union"] = tif.is_union();
        result["is_enum"] = tif.is_enum();

        return result;
    }

    inline nlohmann::json set_type(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("type_string")) {
            throw std::invalid_argument("Missing required parameters: address, type_string");
        }

        ea_t address = args["address"];
        std::string type_string = args["type_string"];
        int flags = args.value("flags", TINFO_DEFINITE);

        tinfo_t tif;
        if (!parse_decl(&tif, nullptr, get_idati(), type_string.c_str(), PT_SIL)) {
            throw std::runtime_error("Failed to parse type declaration: " + type_string);
        }

        bool success = apply_tinfo(address, tif, flags);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json get_tinfo_details(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tinfo_t tif;
        if (!get_tinfo(&tif, address)) {
            throw std::runtime_error("No type information at address");
        }

        qstring type_str, name;
        tif.print(&type_str);
        tif.get_type_name(&name);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["type"] = type_str.c_str();
        result["type_name"] = name.c_str();
        result["size"] = tif.get_size();
        result["is_const"] = tif.is_const();
        result["is_volatile"] = tif.is_volatile();

        return result;
    }

    inline nlohmann::json parse_type_declaration(const nlohmann::json &args) {
        if (!args.contains("declaration")) {
            throw std::invalid_argument("Missing required parameter: declaration");
        }

        std::string decl = args["declaration"];
        int flags = args.value("flags", PT_SIL);

        tinfo_t tif;
        qstring name;
        if (!parse_decl(&tif, &name, get_idati(), decl.c_str(), flags)) {
            throw std::runtime_error("Failed to parse type declaration");
        }

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["type"] = type_str.c_str();
        result["name"] = name.c_str();
        result["size"] = tif.get_size();
        result["success"] = true;

        return result;
    }

    inline nlohmann::json print_type_at(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int flags = args.value("flags", PRTYPE_1LINE);

        qstring type_str;
        if (!print_type(&type_str, address, flags)) {
            throw std::runtime_error("Failed to print type");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["type"] = type_str.c_str();

        return result;
    }

    inline nlohmann::json get_type_size(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tinfo_t tif;
        if (!get_tinfo(&tif, address)) {
            throw std::runtime_error("No type information at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["size"] = tif.get_size();

        return result;
    }

    // Structure/Union/Enum Tools

    inline nlohmann::json get_struct_by_name(const nlohmann::json &args) {
        if (!args.contains("name")) {
            throw std::invalid_argument("Missing required parameter: name");
        }

        std::string name = args["name"];

        tinfo_t tif;
        if (!tif.get_named_type(get_idati(), name.c_str())) {
            throw std::runtime_error("Structure not found: " + name);
        }

        if (!tif.is_struct() && !tif.is_union()) {
            throw std::runtime_error("Type is not a structure or union: " + name);
        }

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["name"] = name;
        result["type"] = type_str.c_str();
        result["size"] = tif.get_size();
        result["is_union"] = tif.is_union();

        return result;
    }

    inline nlohmann::json get_struct_members(const nlohmann::json &args) {
        if (!args.contains("name")) {
            throw std::invalid_argument("Missing required parameter: name");
        }

        std::string name = args["name"];

        tinfo_t tif;
        if (!tif.get_named_type(get_idati(), name.c_str())) {
            throw std::runtime_error("Structure not found: " + name);
        }

        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt)) {
            throw std::runtime_error("Failed to get structure details");
        }

        nlohmann::json members = nlohmann::json::array();
        for (size_t i = 0; i < udt.size(); i++) {
            const udm_t &member = udt[i];

            qstring member_type;
            member.type.print(&member_type);

            nlohmann::json mem;
            mem["name"] = member.name.c_str();
            mem["offset"] = static_cast<uint64_t>(member.offset / 8); // bits to bytes
            mem["size"] = member.size / 8;
            mem["type"] = member_type.c_str();

            members.push_back(mem);
        }

        nlohmann::json result;
        result["name"] = name;
        result["members"] = members;
        result["count"] = members.size();

        return result;
    }

    inline nlohmann::json get_struct_member_at_offset(const nlohmann::json &args) {
        if (!args.contains("name") || !args.contains("offset")) {
            throw std::invalid_argument("Missing required parameters: name, offset");
        }

        std::string name = args["name"];
        uint64_t offset = args["offset"];

        tinfo_t tif;
        if (!tif.get_named_type(get_idati(), name.c_str())) {
            throw std::runtime_error("Structure not found: " + name);
        }

        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt)) {
            throw std::runtime_error("Failed to get structure details");
        }

        // Find member at offset
        for (size_t i = 0; i < udt.size(); i++) {
            const udm_t &member = udt[i];
            uint64_t member_offset = member.offset / 8;

            if (member_offset == offset) {
                qstring member_type;
                member.type.print(&member_type);

                nlohmann::json result;
                result["name"] = member.name.c_str();
                result["offset"] = member_offset;
                result["size"] = member.size / 8;
                result["type"] = member_type.c_str();

                return result;
            }
        }

        throw std::runtime_error("No member found at offset " + std::to_string(offset));
    }

    inline nlohmann::json get_enum_members(const nlohmann::json &args) {
        if (!args.contains("name")) {
            throw std::invalid_argument("Missing required parameter: name");
        }

        std::string name = args["name"];

        tinfo_t tif;
        if (!tif.get_named_type(get_idati(), name.c_str())) {
            throw std::runtime_error("Enum not found: " + name);
        }

        if (!tif.is_enum()) {
            throw std::runtime_error("Type is not an enum: " + name);
        }

        enum_type_data_t etd;
        if (!tif.get_enum_details(&etd)) {
            throw std::runtime_error("Failed to get enum details");
        }

        nlohmann::json members = nlohmann::json::array();
        for (size_t i = 0; i < etd.size(); i++) {
            const edm_t &member = etd[i];

            nlohmann::json mem;
            mem["name"] = member.name.c_str();
            mem["value"] = static_cast<int64_t>(member.value);

            members.push_back(mem);
        }

        nlohmann::json result;
        result["name"] = name;
        result["members"] = members;
        result["count"] = members.size();

        return result;
    }

    // Function Type Tools

    inline nlohmann::json get_function_type(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tinfo_t tif;
        if (!get_tinfo(&tif, address)) {
            throw std::runtime_error("No type information at address");
        }

        if (!tif.is_func()) {
            throw std::runtime_error("Address does not have function type");
        }

        func_type_data_t ftd;
        if (!tif.get_func_details(&ftd)) {
            throw std::runtime_error("Failed to get function details");
        }

        qstring ret_type_str;
        ftd.rettype.print(&ret_type_str);

        nlohmann::json args_array = nlohmann::json::array();
        for (size_t i = 0; i < ftd.size(); i++) {
            const funcarg_t &arg = ftd[i];

            qstring arg_type;
            arg.type.print(&arg_type);

            nlohmann::json arg_obj;
            arg_obj["name"] = arg.name.c_str();
            arg_obj["type"] = arg_type.c_str();

            args_array.push_back(arg_obj);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["return_type"] = ret_type_str.c_str();
        result["arguments"] = args_array;
        result["arg_count"] = ftd.size();
        result["calling_convention"] = ftd.cc;

        return result;
    }

    inline nlohmann::json set_function_type(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("type_string")) {
            throw std::invalid_argument("Missing required parameters: address, type_string");
        }

        ea_t address = args["address"];
        std::string type_string = args["type_string"];

        tinfo_t tif;
        if (!parse_decl(&tif, nullptr, get_idati(), type_string.c_str(), PT_SIL)) {
            throw std::runtime_error("Failed to parse function type declaration");
        }

        if (!tif.is_func()) {
            throw std::runtime_error("Parsed type is not a function type");
        }

        bool success = apply_tinfo(address, tif, TINFO_DEFINITE);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json get_function_return_type(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tinfo_t tif;
        if (!get_tinfo(&tif, address)) {
            throw std::runtime_error("No type information at address");
        }

        if (!tif.is_func()) {
            throw std::runtime_error("Address does not have function type");
        }

        func_type_data_t ftd;
        if (!tif.get_func_details(&ftd)) {
            throw std::runtime_error("Failed to get function details");
        }

        qstring ret_type_str;
        ftd.rettype.print(&ret_type_str);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["return_type"] = ret_type_str.c_str();
        result["size"] = ftd.rettype.get_size();

        return result;
    }

    // Named Type Tools

    inline nlohmann::json get_named_type(const nlohmann::json &args) {
        if (!args.contains("name")) {
            throw std::invalid_argument("Missing required parameter: name");
        }

        std::string name = args["name"];

        tinfo_t tif;
        if (!tif.get_named_type(get_idati(), name.c_str())) {
            throw std::runtime_error("Type not found: " + name);
        }

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["name"] = name;
        result["type"] = type_str.c_str();
        result["size"] = tif.get_size();
        result["is_struct"] = tif.is_struct();
        result["is_union"] = tif.is_union();
        result["is_enum"] = tif.is_enum();
        result["is_typedef"] = tif.is_typedef();

        return result;
    }

    inline nlohmann::json get_numbered_type(const nlohmann::json &args) {
        if (!args.contains("ordinal")) {
            throw std::invalid_argument("Missing required parameter: ordinal");
        }

        uint32_t ordinal = args["ordinal"];

        const type_t *type = nullptr;
        const p_list *fields = nullptr;
        qstring name;

        if (!get_numbered_type(get_idati(), ordinal, &type, &fields, nullptr, nullptr)) {
            throw std::runtime_error("Failed to get type at ordinal " + std::to_string(ordinal));
        }

        get_numbered_type_name(get_idati(), ordinal);

        tinfo_t tif;
        tif.deserialize(get_idati(), &type, &fields);

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["ordinal"] = ordinal;
        result["type"] = type_str.c_str();
        result["size"] = tif.get_size();

        return result;
    }

    // Objective-C Tools

    inline nlohmann::json parse_objc_declaration(const nlohmann::json &args) {
        if (!args.contains("declaration")) {
            throw std::invalid_argument("Missing required parameter: declaration");
        }

        std::string decl = args["declaration"];

        // Select Objective-C parser
        if (!select_parser_by_srclang(SRCLANG_OBJC)) {
            throw std::runtime_error("Objective-C parser not available");
        }

        tinfo_t tif;
        qstring name;
        if (!parse_decl(&tif, &name, get_idati(), decl.c_str(), PT_SIL)) {
            throw std::runtime_error("Failed to parse Objective-C declaration");
        }

        qstring type_str;
        tif.print(&type_str);

        nlohmann::json result;
        result["type"] = type_str.c_str();
        result["name"] = name.c_str();
        result["size"] = tif.get_size();
        result["success"] = true;

        return result;
    }

    inline nlohmann::json parse_declarations(const nlohmann::json &args) {
        if (!args.contains("declarations")) {
            throw std::invalid_argument("Missing required parameter: declarations");
        }

        std::string decls = args["declarations"];
        std::string lang = args.value("language", "C");

        srclang_t srclang = SRCLANG_C;
        if (lang == "CPP" || lang == "C++") {
            srclang = SRCLANG_CPP;
        } else if (lang == "OBJC" || lang == "Objective-C") {
            srclang = SRCLANG_OBJC;
        }

        int errors = parse_decls_for_srclang(srclang, get_idati(), decls.c_str(), false);

        nlohmann::json result;
        result["errors"] = errors;
        result["success"] = (errors == 0);
        result["language"] = lang;

        return result;
    }

    // ===== Control Flow Graph Tools =====

    inline nlohmann::json get_flowchart(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int flags = args.value("flags", 0);

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, flags);

        nlohmann::json blocks = nlohmann::json::array();
        for (int i = 0; i < qfc.blocks.size(); i++) {
            const qbasic_block_t &blk = qfc.blocks[i];

            nlohmann::json block;
            block["id"] = i;
            block["start_ea"] = static_cast<uint64_t>(blk.start_ea);
            block["end_ea"] = static_cast<uint64_t>(blk.end_ea);

            nlohmann::json succs = nlohmann::json::array();
            for (int succ: blk.succ) {
                succs.push_back(succ);
            }
            block["succs"] = succs;

            nlohmann::json preds = nlohmann::json::array();
            for (int pred: blk.pred) {
                preds.push_back(pred);
            }
            block["preds"] = preds;

            fc_block_type_t btype = qfc.calc_block_type(i);
            block["type"] = btype;

            blocks.push_back(block);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["blocks"] = blocks;
        result["block_count"] = qfc.blocks.size();

        return result;
    }

    inline nlohmann::json get_basic_blocks(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

        nlohmann::json blocks = nlohmann::json::array();
        for (int i = 0; i < qfc.blocks.size(); i++) {
            const qbasic_block_t &blk = qfc.blocks[i];

            nlohmann::json block;
            block["id"] = i;
            block["start_ea"] = static_cast<uint64_t>(blk.start_ea);
            block["end_ea"] = static_cast<uint64_t>(blk.end_ea);
            block["size"] = blk.size();

            blocks.push_back(block);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["blocks"] = blocks;
        result["count"] = blocks.size();

        return result;
    }

    inline nlohmann::json get_basic_block_at(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

        // Find block containing address
        for (int i = 0; i < qfc.blocks.size(); i++) {
            const qbasic_block_t &blk = qfc.blocks[i];
            if (blk.contains(address)) {
                nlohmann::json result;
                result["id"] = i;
                result["start_ea"] = static_cast<uint64_t>(blk.start_ea);
                result["end_ea"] = static_cast<uint64_t>(blk.end_ea);
                result["size"] = blk.size();

                nlohmann::json succs = nlohmann::json::array();
                for (int succ: blk.succ) {
                    succs.push_back(succ);
                }
                result["succs"] = succs;

                nlohmann::json preds = nlohmann::json::array();
                for (int pred: blk.pred) {
                    preds.push_back(pred);
                }
                result["preds"] = preds;

                return result;
            }
        }

        throw std::runtime_error("No basic block contains the address");
    }

    inline nlohmann::json get_block_succs(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("block_id")) {
            throw std::invalid_argument("Missing required parameters: address, block_id");
        }

        ea_t address = args["address"];
        int block_id = args["block_id"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

        if (block_id < 0 || block_id >= qfc.blocks.size()) {
            throw std::runtime_error("Invalid block_id");
        }

        const qbasic_block_t &blk = qfc.blocks[block_id];
        nlohmann::json succs = nlohmann::json::array();
        for (int succ: blk.succ) {
            succs.push_back(succ);
        }

        nlohmann::json result;
        result["block_id"] = block_id;
        result["succs"] = succs;
        result["count"] = succs.size();

        return result;
    }

    inline nlohmann::json get_block_preds(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("block_id")) {
            throw std::invalid_argument("Missing required parameters: address, block_id");
        }

        ea_t address = args["address"];
        int block_id = args["block_id"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

        if (block_id < 0 || block_id >= qfc.blocks.size()) {
            throw std::runtime_error("Invalid block_id");
        }

        const qbasic_block_t &blk = qfc.blocks[block_id];
        nlohmann::json preds = nlohmann::json::array();
        for (int pred: blk.pred) {
            preds.push_back(pred);
        }

        nlohmann::json result;
        result["block_id"] = block_id;
        result["preds"] = preds;
        result["count"] = preds.size();

        return result;
    }

    inline nlohmann::json get_block_type(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("block_id")) {
            throw std::invalid_argument("Missing required parameters: address, block_id");
        }

        ea_t address = args["address"];
        int block_id = args["block_id"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        qflow_chart_t qfc("", pfn, pfn->start_ea, pfn->end_ea, 0);

        if (block_id < 0 || block_id >= qfc.blocks.size()) {
            throw std::runtime_error("Invalid block_id");
        }

        fc_block_type_t btype = qfc.calc_block_type(block_id);

        nlohmann::json result;
        result["block_id"] = block_id;
        result["type"] = btype;
        result["is_ret"] = is_ret_block(btype);
        result["is_noret"] = is_noret_block(btype);

        return result;
    }

    // ===== Call Graph Tools =====

    inline nlohmann::json generate_call_graph(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int depth = args.value("depth", 1);

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        // Simple call graph: just get direct callees
        nlohmann::json nodes = nlohmann::json::array();
        nlohmann::json edges = nlohmann::json::array();

        // Add root node
        qstring name;
        get_func_name(&name, pfn->start_ea);
        nlohmann::json root;
        root["address"] = static_cast<uint64_t>(pfn->start_ea);
        root["name"] = name.c_str();
        nodes.push_back(root);

        // Get callees
        xrefblk_t xb;
        for (ea_t ea = pfn->start_ea; ea < pfn->end_ea;) {
            for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                    func_t *callee = get_func(xb.to);
                    if (callee) {
                        qstring callee_name;
                        get_func_name(&callee_name, callee->start_ea);

                        nlohmann::json node;
                        node["address"] = static_cast<uint64_t>(callee->start_ea);
                        node["name"] = callee_name.c_str();
                        nodes.push_back(node);

                        nlohmann::json edge;
                        edge["from"] = static_cast<uint64_t>(pfn->start_ea);
                        edge["to"] = static_cast<uint64_t>(callee->start_ea);
                        edge["call_site"] = static_cast<uint64_t>(ea);
                        edges.push_back(edge);
                    }
                }
            }
            ea = next_head(ea, pfn->end_ea);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["nodes"] = nodes;
        result["edges"] = edges;
        result["node_count"] = nodes.size();
        result["edge_count"] = edges.size();

        return result;
    }

    inline nlohmann::json get_caller_graph(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int depth = args.value("depth", 1);

        nlohmann::json callers = nlohmann::json::array();

        xrefblk_t xb;
        for (bool ok = xb.first_to(address, XREF_ALL); ok; ok = xb.next_to()) {
            if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                func_t *caller = get_func(xb.from);
                if (caller) {
                    qstring name;
                    get_func_name(&name, caller->start_ea);

                    nlohmann::json caller_info;
                    caller_info["address"] = static_cast<uint64_t>(caller->start_ea);
                    caller_info["name"] = name.c_str();
                    caller_info["call_site"] = static_cast<uint64_t>(xb.from);

                    callers.push_back(caller_info);
                }
            }
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["callers"] = callers;
        result["count"] = callers.size();
        result["depth"] = depth;

        return result;
    }

    inline nlohmann::json get_callee_graph(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        int depth = args.value("depth", 1);

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        nlohmann::json callees = nlohmann::json::array();

        xrefblk_t xb;
        for (ea_t ea = pfn->start_ea; ea < pfn->end_ea;) {
            for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (xb.iscode && (xb.type == fl_CN || xb.type == fl_CF)) {
                    func_t *callee = get_func(xb.to);
                    if (callee) {
                        qstring name;
                        get_func_name(&name, callee->start_ea);

                        nlohmann::json callee_info;
                        callee_info["address"] = static_cast<uint64_t>(callee->start_ea);
                        callee_info["name"] = name.c_str();
                        callee_info["call_site"] = static_cast<uint64_t>(ea);

                        callees.push_back(callee_info);
                    }
                }
            }
            ea = next_head(ea, pfn->end_ea);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["callees"] = callees;
        result["count"] = callees.size();
        result["depth"] = depth;

        return result;
    }

    // ===== Stack Frame Analysis Tools =====

    inline nlohmann::json get_frame(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        tinfo_t frame_tif;
        if (!get_func_frame(&frame_tif, pfn)) {
            throw std::runtime_error("Failed to get function frame");
        }

        qstring frame_str;
        frame_tif.print(&frame_str);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["frame_type"] = frame_str.c_str();
        result["frame_size"] = get_frame_size(pfn);
        result["frsize"] = pfn->frsize;
        result["frregs"] = pfn->frregs;
        result["argsize"] = pfn->argsize;

        return result;
    }

    inline nlohmann::json get_frame_size(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["size"] = ::get_frame_size(pfn);

        return result;
    }

    inline nlohmann::json get_stack_vars(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        tinfo_t frame_tif;
        if (!get_func_frame(&frame_tif, pfn)) {
            throw std::runtime_error("Failed to get function frame");
        }

        udt_type_data_t udt;
        if (!frame_tif.get_udt_details(&udt)) {
            throw std::runtime_error("Failed to get frame details");
        }

        nlohmann::json vars = nlohmann::json::array();
        for (size_t i = 0; i < udt.size(); i++) {
            const udm_t &member = udt[i];

            qstring member_type;
            member.type.print(&member_type);

            nlohmann::json var;
            var["name"] = member.name.c_str();
            var["offset"] = static_cast<int64_t>(member.offset / 8);
            var["size"] = member.size / 8;
            var["type"] = member_type.c_str();

            vars.push_back(var);
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["vars"] = vars;
        result["count"] = vars.size();

        return result;
    }

    inline nlohmann::json get_stack_var_at(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("offset")) {
            throw std::invalid_argument("Missing required parameters: address, offset");
        }

        ea_t address = args["address"];
        int64_t offset = args["offset"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        tinfo_t frame_tif;
        if (!get_func_frame(&frame_tif, pfn)) {
            throw std::runtime_error("Failed to get function frame");
        }

        udt_type_data_t udt;
        if (!frame_tif.get_udt_details(&udt)) {
            throw std::runtime_error("Failed to get frame details");
        }

        for (size_t i = 0; i < udt.size(); i++) {
            const udm_t &member = udt[i];
            int64_t member_offset = member.offset / 8;

            if (member_offset == offset) {
                qstring member_type;
                member.type.print(&member_type);

                nlohmann::json result;
                result["name"] = member.name.c_str();
                result["offset"] = member_offset;
                result["size"] = member.size / 8;
                result["type"] = member_type.c_str();

                return result;
            }
        }

        throw std::runtime_error("No stack variable at offset " + std::to_string(offset));
    }

    inline nlohmann::json get_frame_args(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        range_t args_range;
        get_frame_part(&args_range, pfn, FPC_ARGS);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["args_start"] = static_cast<int64_t>(args_range.start_ea);
        result["args_end"] = static_cast<int64_t>(args_range.end_ea);
        result["args_size"] = args_range.size();

        return result;
    }

    inline nlohmann::json get_frame_locals(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *pfn = get_func(address);
        if (!pfn) {
            throw std::runtime_error("No function at address");
        }

        range_t lvars_range;
        get_frame_part(&lvars_range, pfn, FPC_LVARS);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(pfn->start_ea);
        result["lvars_start"] = static_cast<int64_t>(lvars_range.start_ea);
        result["lvars_end"] = static_cast<int64_t>(lvars_range.end_ea);
        result["lvars_size"] = lvars_range.size();

        return result;
    }

    // ===== Import/Export Tables Tools =====

    inline nlohmann::json get_import_modules(const nlohmann::json &args) {
        nlohmann::json modules = nlohmann::json::array();

        uint mod_qty = get_import_module_qty();
        for (uint i = 0; i < mod_qty; i++) {
            qstring mod_name;
            get_import_module_name(&mod_name, i);

            nlohmann::json mod;
            mod["index"] = i;
            mod["name"] = mod_name.c_str();

            modules.push_back(mod);
        }

        nlohmann::json result;
        result["modules"] = modules;
        result["count"] = modules.size();

        return result;
    }

    inline nlohmann::json get_imports(const nlohmann::json &args) {
        if (!args.contains("module_index")) {
            throw std::invalid_argument("Missing required parameter: module_index");
        }

        int module_index = args["module_index"];

        qstring mod_name;
        get_import_module_name(&mod_name, module_index);

        nlohmann::json imports = nlohmann::json::array();

        struct import_collector_t {
            nlohmann::json *imports;

            static int idaapi callback(ea_t ea, const char *name, uval_t ord, void *param) {
                import_collector_t *ctx = (import_collector_t *) param;

                nlohmann::json imp;
                imp["address"] = static_cast<uint64_t>(ea);
                imp["name"] = name ? name : "";
                imp["ordinal"] = static_cast<uint64_t>(ord);

                ctx->imports->push_back(imp);
                return 1; // continue enumeration
            }
        };

        import_collector_t ctx;
        ctx.imports = &imports;
        enum_import_names(module_index, import_collector_t::callback, &ctx);

        nlohmann::json result;
        result["module_index"] = module_index;
        result["module_name"] = mod_name.c_str();
        result["imports"] = imports;
        result["count"] = imports.size();

        return result;
    }

    inline nlohmann::json enum_imports(const nlohmann::json &args) {
        nlohmann::json all_imports = nlohmann::json::array();

        uint mod_qty = get_import_module_qty();
        for (uint i = 0; i < mod_qty; i++) {
            qstring mod_name;
            get_import_module_name(&mod_name, i);

            nlohmann::json imports = nlohmann::json::array();

            struct import_collector_t {
                nlohmann::json *imports;

                static int idaapi callback(ea_t ea, const char *name, uval_t ord, void *param) {
                    import_collector_t *ctx = (import_collector_t *) param;

                    nlohmann::json imp;
                    imp["address"] = static_cast<uint64_t>(ea);
                    imp["name"] = name ? name : "";
                    imp["ordinal"] = static_cast<uint64_t>(ord);

                    ctx->imports->push_back(imp);
                    return 1;
                }
            };

            import_collector_t ctx;
            ctx.imports = &imports;
            enum_import_names(i, import_collector_t::callback, &ctx);

            nlohmann::json mod;
            mod["module_name"] = mod_name.c_str();
            mod["imports"] = imports;
            mod["count"] = imports.size();

            all_imports.push_back(mod);
        }

        nlohmann::json result;
        result["modules"] = all_imports;
        result["module_count"] = all_imports.size();

        return result;
    }

    inline nlohmann::json get_export_count(const nlohmann::json &args) {
        nlohmann::json result;
        result["count"] = get_entry_qty();

        return result;
    }

    inline nlohmann::json get_exports(const nlohmann::json &args) {
        nlohmann::json exports = nlohmann::json::array();

        size_t qty = get_entry_qty();
        for (size_t i = 0; i < qty; i++) {
            uval_t ord = get_entry_ordinal(i);
            ea_t ea = get_entry(ord);

            qstring name;
            get_entry_name(&name, ord);

            nlohmann::json exp;
            exp["index"] = i;
            exp["ordinal"] = static_cast<uint64_t>(ord);
            exp["address"] = static_cast<uint64_t>(ea);
            exp["name"] = name.c_str();

            exports.push_back(exp);
        }

        nlohmann::json result;
        result["exports"] = exports;
        result["count"] = exports.size();

        return result;
    }

    // ===== Entry Points Tools =====

    inline nlohmann::json get_entry_points(const nlohmann::json &args) {
        nlohmann::json entries = nlohmann::json::array();

        size_t qty = get_entry_qty();
        for (size_t i = 0; i < qty; i++) {
            uval_t ord = get_entry_ordinal(i);
            ea_t ea = get_entry(ord);

            qstring name;
            get_entry_name(&name, ord);

            nlohmann::json entry;
            entry["index"] = i;
            entry["ordinal"] = static_cast<uint64_t>(ord);
            entry["address"] = static_cast<uint64_t>(ea);
            entry["name"] = name.c_str();

            entries.push_back(entry);
        }

        nlohmann::json result;
        result["entries"] = entries;
        result["count"] = entries.size();

        return result;
    }

    inline nlohmann::json get_entry_point(const nlohmann::json &args) {
        if (!args.contains("ordinal")) {
            throw std::invalid_argument("Missing required parameter: ordinal");
        }

        uval_t ordinal = args["ordinal"];

        ea_t ea = get_entry(ordinal);
        if (ea == BADADDR) {
            throw std::runtime_error("Entry point not found");
        }

        qstring name;
        get_entry_name(&name, ordinal);

        nlohmann::json result;
        result["ordinal"] = static_cast<uint64_t>(ordinal);
        result["address"] = static_cast<uint64_t>(ea);
        result["name"] = name.c_str();

        return result;
    }

    inline nlohmann::json get_entry_name(const nlohmann::json &args) {
        if (!args.contains("ordinal")) {
            throw std::invalid_argument("Missing required parameter: ordinal");
        }

        uval_t ordinal = args["ordinal"];

        qstring name;
        if (::get_entry_name(&name, ordinal) < 0) {
            throw std::runtime_error("Entry point not found");
        }

        nlohmann::json result;
        result["ordinal"] = static_cast<uint64_t>(ordinal);
        result["name"] = name.c_str();

        return result;
    }

    // ===== Pattern Search Tools =====

    inline nlohmann::json search_binary(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("pattern")) {
            throw std::invalid_argument("Missing required parameters: start_ea, pattern");
        }

        ea_t start_ea = args["start_ea"];
        ea_t end_ea = args.value("end_ea", BADADDR);
        std::string pattern = args["pattern"];
        int flags = args.value("flags", SEARCH_DOWN);

        compiled_binpat_vec_t compiled;
        qstring error_msg;

        if (!parse_binpat_str(&compiled, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &error_msg)) {
            throw std::runtime_error("Failed to parse pattern: " + std::string(error_msg.c_str()));
        }

        ea_t found = bin_search(start_ea, end_ea, compiled, flags);

        nlohmann::json result;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["pattern"] = pattern;
        result["found"] = (found != BADADDR);
        if (found != BADADDR) {
            result["address"] = static_cast<uint64_t>(found);
        }

        return result;
    }

    inline nlohmann::json find_pattern(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("pattern")) {
            throw std::invalid_argument("Missing required parameters: start_ea, pattern");
        }

        ea_t start_ea = args["start_ea"];
        ea_t end_ea = args.value("end_ea", BADADDR);
        std::string pattern = args["pattern"];
        int flags = args.value("flags", SEARCH_DOWN);

        compiled_binpat_vec_t compiled;
        qstring error_msg;

        if (!parse_binpat_str(&compiled, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &error_msg)) {
            throw std::runtime_error("Failed to parse pattern: " + std::string(error_msg.c_str()));
        }

        nlohmann::json matches = nlohmann::json::array();
        int limit = args.value("limit", 100);

        ea_t ea = start_ea;
        for (int i = 0; i < limit; i++) {
            ea = bin_search(ea, end_ea, compiled, flags);
            if (ea == BADADDR) break;

            matches.push_back(static_cast<uint64_t>(ea));
            ea = next_head(ea, end_ea);
            if (ea == BADADDR) break;
        }

        nlohmann::json result;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["pattern"] = pattern;
        result["matches"] = matches;
        result["count"] = matches.size();

        return result;
    }

    inline nlohmann::json search_text(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("text")) {
            throw std::invalid_argument("Missing required parameters: start_ea, text");
        }

        ea_t start_ea = args["start_ea"];
        std::string text = args["text"];
        int flags = args.value("flags", SEARCH_DOWN);

        ea_t found = find_text(start_ea, 0, 0, text.c_str(), flags);

        nlohmann::json result;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["text"] = text;
        result["found"] = (found != BADADDR);
        if (found != BADADDR) {
            result["address"] = static_cast<uint64_t>(found);
        }

        return result;
    }

    // ===== Fixups/Relocations Tools =====

    inline nlohmann::json get_fixup(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        fixup_data_t fd;
        if (!get_fixup(&fd, address)) {
            throw std::runtime_error("No fixup at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["type"] = fd.get_type();
        result["flags"] = fd.get_flags();
        result["displacement"] = static_cast<int64_t>(fd.displacement);
        result["sel"] = fd.sel;
        result["off"] = static_cast<uint64_t>(fd.off);

        return result;
    }

    inline nlohmann::json get_all_fixups(const nlohmann::json &args) {
        ea_t start_ea = args.value("start_ea", 0);
        ea_t end_ea = args.value("end_ea", BADADDR);

        nlohmann::json fixups = nlohmann::json::array();

        ea_t ea = start_ea;
        fixup_data_t fd;
        while ((ea = get_next_fixup_ea(ea)) != BADADDR && ea < end_ea) {
            if (get_fixup(&fd, ea)) {
                nlohmann::json fixup;
                fixup["address"] = static_cast<uint64_t>(ea);
                fixup["type"] = fd.get_type();
                fixup["flags"] = fd.get_flags();
                fixup["displacement"] = static_cast<int64_t>(fd.displacement);
                fixup["sel"] = fd.sel;
                fixup["off"] = static_cast<uint64_t>(fd.off);

                fixups.push_back(fixup);
            }
        }

        nlohmann::json result;
        result["fixups"] = fixups;
        result["count"] = fixups.size();

        return result;
    }

    inline nlohmann::json contains_fixups(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("end_ea")) {
            throw std::invalid_argument("Missing required parameters: start_ea, end_ea");
        }

        ea_t start_ea = args["start_ea"];
        ea_t end_ea = args["end_ea"];

        bool has_fixups = ::contains_fixups(start_ea, end_ea - start_ea);

        nlohmann::json result;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["end_ea"] = static_cast<uint64_t>(end_ea);
        result["has_fixups"] = has_fixups;

        return result;
    }

    // ===== Jump Tables Tools =====

    inline nlohmann::json get_jump_table(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        switch_info_t si;
        if (!get_switch_info(&si, address)) {
            throw std::runtime_error("No switch info at address");
        }

        nlohmann::json cases = nlohmann::json::array();
        for (int i = 0; i < si.get_jtable_size(); i++) {
            ea_t target = get_jtable_target(address, si, i);
            if (target != BADADDR) {
                cases.push_back(static_cast<uint64_t>(target));
            }
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["ncases"] = si.get_jtable_size();
        result["jumps"] = static_cast<uint64_t>(si.jumps);
        result["cases"] = cases;

        return result;
    }

    inline nlohmann::json get_switch_info(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        switch_info_t si;
        if (!get_switch_info(&si, address)) {
            throw std::runtime_error("No switch info at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["flags"] = si.flags;
        result["ncases"] = si.get_jtable_size();
        result["jumps"] = static_cast<uint64_t>(si.jumps);
        result["lowcase"] = static_cast<int64_t>(si.lowcase);
        result["startea"] = static_cast<uint64_t>(si.startea);

        return result;
    }

    // ===== Advanced Demangling Tools =====

    inline nlohmann::json demangle_name(const nlohmann::json &args) {
        if (!args.contains("name")) {
            throw std::invalid_argument("Missing required parameter: name");
        }

        std::string name = args["name"];
        int flags = args.value("flags", 0);

        qstring demangled;
        int result_code = ::demangle_name(&demangled, name.c_str(), flags);

        nlohmann::json result;
        result["name"] = name;
        result["demangled"] = demangled.c_str();
        result["success"] = (result_code >= 0);

        return result;
    }

    inline nlohmann::json demangle_type(const nlohmann::json &args) {
        if (!args.contains("type_string")) {
            throw std::invalid_argument("Missing required parameter: type_string");
        }

        std::string type_string = args["type_string"];
        bool short_form = args.value("short_form", false);

        qstring demangled;
        int result_code = ::demangle_name(&demangled, type_string.c_str(), short_form ? MNG_SHORT_FORM : 0);

        nlohmann::json result;
        result["type_string"] = type_string;
        result["demangled"] = demangled.c_str();
        result["success"] = (result_code >= 0);

        return result;
    }

    // ===== Operand Analysis Tools =====

    inline nlohmann::json get_operand_type(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("operand_index")) {
            throw std::invalid_argument("Missing required parameters: address, operand_index");
        }

        ea_t address = args["address"];
        int operand_index = args["operand_index"];

        insn_t insn;
        if (decode_insn(&insn, address) == 0) {
            throw std::runtime_error("Failed to decode instruction");
        }

        if (operand_index < 0 || operand_index >= UA_MAXOP) {
            throw std::invalid_argument("Invalid operand index");
        }

        const op_t &op = insn.ops[operand_index];

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["operand_index"] = operand_index;
        result["type"] = op.type;
        result["dtype"] = op.dtype;
        result["flags"] = op.flags;

        if (op.type == o_reg) {
            result["reg"] = op.reg;
        } else if (op.type == o_imm) {
            result["value"] = static_cast<uint64_t>(op.value);
        } else if (op.type == o_mem || op.type == o_near || op.type == o_far) {
            result["addr"] = static_cast<uint64_t>(op.addr);
        } else if (op.type == o_displ) {
            result["addr"] = static_cast<uint64_t>(op.addr);
            result["phrase"] = op.phrase;
        }

        return result;
    }

    inline nlohmann::json get_operand_value(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("operand_index")) {
            throw std::invalid_argument("Missing required parameters: address, operand_index");
        }

        ea_t address = args["address"];
        int operand_index = args["operand_index"];

        insn_t insn;
        if (decode_insn(&insn, address) == 0) {
            throw std::runtime_error("Failed to decode instruction");
        }

        if (operand_index < 0 || operand_index >= UA_MAXOP) {
            throw std::invalid_argument("Invalid operand index");
        }

        uval_t value = insn.ops[operand_index].value;

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["operand_index"] = operand_index;
        result["value"] = static_cast<uint64_t>(value);

        return result;
    }

    inline nlohmann::json get_canon_feature(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        insn_t insn;
        if (decode_insn(&insn, address) == 0) {
            throw std::runtime_error("Failed to decode instruction");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["itype"] = insn.itype;
        result["size"] = insn.size;
        result["feature"] = insn.get_canon_feature(PH);

        return result;
    }

    // ===== Data Analysis Tools =====

    inline nlohmann::json get_data_type(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        flags64_t flags = get_flags(address);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["is_byte"] = is_byte(flags);
        result["is_word"] = is_word(flags);
        result["is_dword"] = is_dword(flags);
        result["is_qword"] = is_qword(flags);
        result["is_oword"] = is_oword(flags);
        result["is_float"] = is_float(flags);
        result["is_double"] = is_double(flags);
        result["is_strlit"] = is_strlit(flags);
        result["is_struct"] = is_struct(flags);
        result["is_align"] = is_align(flags);

        return result;
    }

    inline nlohmann::json get_array_info(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        array_parameters_t ar;
        if (!get_array_parameters(&ar, address)) {
            throw std::runtime_error("No array at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["flags"] = ar.flags;
        result["lineitems"] = ar.lineitems;
        result["alignment"] = ar.alignment;

        return result;
    }

    inline nlohmann::json get_struc_id(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        tid_t struc_id = get_strid(address);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["struc_id"] = static_cast<uint64_t>(struc_id);
        result["has_struct"] = (struc_id != BADADDR);

        return result;
    }

    inline nlohmann::json is_code(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        flags64_t flags = get_flags(address);
        bool code = ::is_code(flags);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["is_code"] = code;

        return result;
    }

    inline nlohmann::json is_data(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        flags64_t flags = get_flags(address);
        bool data = ::is_data(flags);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["is_data"] = data;

        return result;
    }

    inline nlohmann::json is_unknown(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        flags64_t flags = get_flags(address);
        bool unknown = ::is_unknown(flags);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["is_unknown"] = unknown;

        return result;
    }

    // ===== Database Metadata Tools =====

    inline nlohmann::json get_imagebase(const nlohmann::json &args) {
        ea_t imagebase = ::get_imagebase();

        nlohmann::json result;
        result["imagebase"] = static_cast<uint64_t>(imagebase);

        return result;
    }

    inline nlohmann::json get_root_filename(const nlohmann::json &args) {
        char buf[QMAXPATH];
        ::get_root_filename(buf, sizeof(buf));

        nlohmann::json result;
        result["filename"] = buf;

        return result;
    }

    inline nlohmann::json get_input_file_path(const nlohmann::json &args) {
        char buf[QMAXPATH];
        ::get_input_file_path(buf, sizeof(buf));

        nlohmann::json result;
        result["path"] = buf;

        return result;
    }

    // ===== Debugging Tools =====

    inline nlohmann::json set_bpt(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        asize_t size = args.value("size", 0);
        bpttype_t type = static_cast<bpttype_t>(args.value("type", BPT_SOFT));

        bool success = add_bpt(address, size, type);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json del_bpt(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        bool success = ::del_bpt(address);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json enable_bpt(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        bool enable = args.value("enable", true);
        bool success = ::enable_bpt(address, enable);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["enabled"] = enable;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json get_bpt(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        bpt_t bpt;

        if (!::get_bpt(address, &bpt)) {
            throw std::runtime_error("No breakpoint at address");
        }

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(bpt.ea);
        result["size"] = bpt.size;
        result["type"] = bpt.type;
        result["enabled"] = bpt.enabled();

        return result;
    }

    inline nlohmann::json get_thread_qty(const nlohmann::json &args) {
        int qty = ::get_thread_qty();

        nlohmann::json result;
        result["count"] = qty;

        return result;
    }

    inline nlohmann::json get_threads(const nlohmann::json &args) {
        int qty = ::get_thread_qty();

        nlohmann::json threads = nlohmann::json::array();
        for (int i = 0; i < qty; i++) {
            const char *name = getn_thread_name(i);

            nlohmann::json thread;
            thread["id"] = i;
            thread["name"] = name ? name : "";

            threads.push_back(thread);
        }

        nlohmann::json result;
        result["threads"] = threads;
        result["count"] = qty;

        return result;
    }

    inline nlohmann::json select_thread(const nlohmann::json &args) {
        if (!args.contains("thread_id")) {
            throw std::invalid_argument("Missing required parameter: thread_id");
        }

        int thread_id = args["thread_id"];
        bool success = ::select_thread(thread_id);

        nlohmann::json result;
        result["thread_id"] = thread_id;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json start_process(const nlohmann::json &args) {
        std::string path = args.value("path", "");
        std::string args_str = args.value("args", "");
        std::string sdir = args.value("working_dir", "");

        int result_code = ::start_process(path.c_str(), args_str.c_str(), sdir.c_str());

        nlohmann::json result;
        result["result_code"] = result_code;
        result["success"] = (result_code == 1);

        return result;
    }

    inline nlohmann::json exit_process(const nlohmann::json &args) {
        bool success = ::exit_process();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json suspend_process(const nlohmann::json &args) {
        bool success = ::suspend_process();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json resume_process(const nlohmann::json &args) {
        // Resume process
        bool success = ::continue_process();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json step_into(const nlohmann::json &args) {
        bool success = request_step_into();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json step_over(const nlohmann::json &args) {
        bool success = request_step_over();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json step_until_ret(const nlohmann::json &args) {
        bool success = request_step_until_ret();

        nlohmann::json result;
        result["success"] = success;

        return result;
    }

    // ===== Function Modification Tools =====

    inline nlohmann::json set_func_name(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("name")) {
            throw std::invalid_argument("Missing required parameters: address, name");
        }

        ea_t address = args["address"];
        std::string name = args["name"];

        func_t *func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }

        bool success = ::set_name(func->start_ea, name.c_str(), SN_NOWARN);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(func->start_ea);
        result["name"] = name;
        result["success"] = success;

        return result;
    }

    inline nlohmann::json del_func(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        bool success = ::del_func(address);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json add_func(const nlohmann::json &args) {
        if (!args.contains("start")) {
            throw std::invalid_argument("Missing required parameter: start");
        }

        ea_t start = args["start"];
        ea_t end = args.value("end", BADADDR);

        bool success = ::add_func(start, end);

        nlohmann::json result;
        result["start"] = static_cast<uint64_t>(start);
        if (end != BADADDR) {
            result["end"] = static_cast<uint64_t>(end);
        }
        result["success"] = success;

        return result;
    }

    inline nlohmann::json set_func_start(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("new_start")) {
            throw std::invalid_argument("Missing required parameters: address, new_start");
        }

        ea_t address = args["address"];
        ea_t new_start = args["new_start"];

        func_t *func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }

        bool success = ::set_func_start(func->start_ea, new_start);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["new_start"] = static_cast<uint64_t>(new_start);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json set_func_end(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("new_end")) {
            throw std::invalid_argument("Missing required parameters: address, new_end");
        }

        ea_t address = args["address"];
        ea_t new_end = args["new_end"];

        func_t *func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }

        bool success = ::set_func_end(func->start_ea, new_end);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["new_end"] = static_cast<uint64_t>(new_end);
        result["success"] = success;

        return result;
    }

    inline nlohmann::json reanalyze_function(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        func_t *func = get_func(address);
        if (!func) {
            throw std::runtime_error("No function at address");
        }

        // Force reanalysis
        plan_range(func->start_ea, func->end_ea);
        auto_wait();

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["success"] = true;

        return result;
    }

    // ===== Cross-Reference Enhancement Tools =====

    inline nlohmann::json add_cref(const nlohmann::json &args) {
        if (!args.contains("from") || !args.contains("to")) {
            throw std::invalid_argument("Missing required parameters: from, to");
        }

        ea_t from = args["from"];
        ea_t to = args["to"];
        cref_t type = static_cast<cref_t>(args.value("type", fl_CN));

        add_cref(from, to, type);

        nlohmann::json result;
        result["from"] = static_cast<uint64_t>(from);
        result["to"] = static_cast<uint64_t>(to);
        result["type"] = type;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json add_dref(const nlohmann::json &args) {
        if (!args.contains("from") || !args.contains("to")) {
            throw std::invalid_argument("Missing required parameters: from, to");
        }

        ea_t from = args["from"];
        ea_t to = args["to"];
        dref_t type = static_cast<dref_t>(args.value("type", dr_O));

        add_dref(from, to, type);

        nlohmann::json result;
        result["from"] = static_cast<uint64_t>(from);
        result["to"] = static_cast<uint64_t>(to);
        result["type"] = type;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json del_cref(const nlohmann::json &args) {
        if (!args.contains("from") || !args.contains("to")) {
            throw std::invalid_argument("Missing required parameters: from, to");
        }

        ea_t from = args["from"];
        ea_t to = args["to"];
        bool expand = args.value("expand", true);

        ::del_cref(from, to, expand);

        nlohmann::json result;
        result["from"] = static_cast<uint64_t>(from);
        result["to"] = static_cast<uint64_t>(to);
        result["success"] = true;

        return result;
    }

    inline nlohmann::json del_dref(const nlohmann::json &args) {
        if (!args.contains("from") || !args.contains("to")) {
            throw std::invalid_argument("Missing required parameters: from, to");
        }

        ea_t from = args["from"];
        ea_t to = args["to"];

        ::del_dref(from, to);

        nlohmann::json result;
        result["from"] = static_cast<uint64_t>(from);
        result["to"] = static_cast<uint64_t>(to);
        result["success"] = true;

        return result;
    }

    // ===== Patching Tools =====

    // Helper function to parse value from JSON (supports both integer and hex string)
    inline uint64_t parse_patch_value(const nlohmann::json &value_json) {
        if (value_json.is_number()) {
            return value_json.get<uint64_t>();
        } else if (value_json.is_string()) {
            std::string value_str = value_json.get<std::string>();
            char *end;
            uint64_t value = std::strtoull(value_str.c_str(), &end, 0);
            if (end == value_str.c_str() || *end != '\0') {
                throw std::invalid_argument("Invalid value format: " + value_str);
            }
            return value;
        } else {
            throw std::invalid_argument("Value must be an integer or hex string");
        }
    }

    inline nlohmann::json patch_byte(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("value")) {
            throw std::invalid_argument("Missing required parameters: address, value");
        }

        ea_t address = args["address"];
        uint64_t value = parse_patch_value(args["value"]);

        ::patch_byte(address, value);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = static_cast<uint64_t>(value & 0xFF);
        result["success"] = true;

        return result;
    }

    inline nlohmann::json patch_word(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("value")) {
            throw std::invalid_argument("Missing required parameters: address, value");
        }

        ea_t address = args["address"];
        uint64_t value = parse_patch_value(args["value"]);

        ::patch_word(address, value);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = static_cast<uint64_t>(value & 0xFFFF);
        result["success"] = true;

        return result;
    }

    inline nlohmann::json patch_dword(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("value")) {
            throw std::invalid_argument("Missing required parameters: address, value");
        }

        ea_t address = args["address"];
        uint64_t value = parse_patch_value(args["value"]);

        ::patch_dword(address, value);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = static_cast<uint64_t>(value & 0xFFFFFFFF);
        result["success"] = true;

        return result;
    }

    inline nlohmann::json patch_qword(const nlohmann::json &args) {
        if (!args.contains("address") || !args.contains("value")) {
            throw std::invalid_argument("Missing required parameters: address, value");
        }

        ea_t address = args["address"];
        uint64_t value = parse_patch_value(args["value"]);

        ::patch_qword(address, value);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = value;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json get_original_byte(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];
        uint8_t value = ::get_original_byte(address);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = value;

        return result;
    }

    inline nlohmann::json revert_byte(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        uint8_t orig = ::get_original_byte(address);
        ::patch_byte(address, orig);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        result["value"] = orig;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json visit_patched_bytes(const nlohmann::json &args) {
        ea_t start_ea = args.value("start_ea", 0);
        ea_t end_ea = args.value("end_ea", BADADDR);
        int limit = args.value("limit", 1000);

        nlohmann::json patches = nlohmann::json::array();
        int count = 0;

        ea_t ea = start_ea;
        while (ea < end_ea && count < limit) {
            ea = next_that(ea, end_ea, [](flags64_t f, void *) { return has_value(f); }, nullptr);
            if (ea == BADADDR) break;

            uint8_t current = get_byte(ea);
            uint8_t original = get_original_byte(ea);

            if (current != original) {
                nlohmann::json patch;
                patch["address"] = static_cast<uint64_t>(ea);
                patch["original"] = original;
                patch["patched"] = current;
                patches.push_back(patch);
                count++;
            }

            ea = next_head(ea, end_ea);
        }

        nlohmann::json result;
        result["patches"] = patches;
        result["count"] = count;

        return result;
    }

    // ===== Search Enhancement Tools =====

    inline nlohmann::json find_binary_ex(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("pattern")) {
            throw std::invalid_argument("Missing required parameters: start_ea, pattern");
        }

        ea_t start_ea = args["start_ea"];
        ea_t end_ea = args.value("end_ea", BADADDR);
        std::string pattern = args["pattern"];
        int flags = args.value("flags", SEARCH_DOWN);

        compiled_binpat_vec_t bv;
        qstring error_msg;
        if (!parse_binpat_str(&bv, start_ea, pattern.c_str(), 16, PBSENC_DEF1BPU, &error_msg)) {
            throw std::runtime_error("Invalid pattern: " + std::string(error_msg.c_str()));
        }

        ea_t result_ea = bin_search(start_ea, end_ea, bv, flags);

        nlohmann::json result;
        if (result_ea != BADADDR) {
            result["address"] = static_cast<uint64_t>(result_ea);
        } else {
            result["address"] = nlohmann::json();
        }
        result["found"] = (result_ea != BADADDR);

        return result;
    }

    inline nlohmann::json find_text_ex(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("text")) {
            throw std::invalid_argument("Missing required parameters: start_ea, text");
        }

        ea_t start_ea = args["start_ea"];
        std::string text = args["text"];
        int flags = args.value("flags", SEARCH_DOWN);

        ea_t result_ea = find_text(start_ea, 0, 0, text.c_str(), flags);

        nlohmann::json result;
        if (result_ea != BADADDR) {
            result["address"] = static_cast<uint64_t>(result_ea);
        } else {
            result["address"] = nlohmann::json();
        }
        result["found"] = (result_ea != BADADDR);

        return result;
    }

    inline nlohmann::json find_all_text(const nlohmann::json &args) {
        if (!args.contains("text")) {
            throw std::invalid_argument("Missing required parameter: text");
        }

        std::string text = args["text"];
        ea_t start_ea = args.value("start_ea", 0);
        ea_t end_ea = args.value("end_ea", BADADDR);
        int limit = args.value("limit", 100);
        int flags = args.value("flags", SEARCH_DOWN);

        nlohmann::json matches = nlohmann::json::array();

        ea_t ea = start_ea;
        int count = 0;
        while (count < limit) {
            ea = find_text(ea, 0, 0, text.c_str(), flags);
            if (ea == BADADDR || ea >= end_ea) break;

            matches.push_back(static_cast<uint64_t>(ea));
            count++;

            ea = next_head(ea, end_ea);
        }

        nlohmann::json result;
        result["matches"] = matches;
        result["count"] = count;

        return result;
    }

    inline nlohmann::json find_next_addr(const nlohmann::json &args) {
        if (!args.contains("address")) {
            throw std::invalid_argument("Missing required parameter: address");
        }

        ea_t address = args["address"];

        ea_t next = next_head(address, BADADDR);

        nlohmann::json result;
        result["address"] = static_cast<uint64_t>(address);
        if (next != BADADDR) {
            result["next"] = static_cast<uint64_t>(next);
        } else {
            result["next"] = nlohmann::json();
        }

        return result;
    }

    // ===== Bookmarks/Navigation Tools =====


    // ===== Disassembly Output Tools =====

    inline nlohmann::json gen_disasm_text(const nlohmann::json &args) {
        if (!args.contains("start_ea") || !args.contains("end_ea")) {
            throw std::invalid_argument("Missing required parameters: start_ea, end_ea");
        }

        ea_t start_ea = args["start_ea"];
        ea_t end_ea = args["end_ea"];
        bool as_stack = args.value("as_stack", false);

        text_t disasm;
        gen_disasm_text(disasm, start_ea, end_ea, as_stack);

        std::string text;
        for (const auto &tw: disasm) {
            text += tw.line.c_str();
            text += "\n";
        }

        nlohmann::json result;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["end_ea"] = static_cast<uint64_t>(end_ea);
        result["text"] = text;

        return result;
    }

    inline nlohmann::json tag_remove(const nlohmann::json &args) {
        if (!args.contains("text")) {
            throw std::invalid_argument("Missing required parameter: text");
        }

        std::string text = args["text"];
        qstring stripped = text.c_str();
        ::tag_remove(&stripped);

        nlohmann::json result;
        result["original"] = text;
        result["stripped"] = stripped.c_str();

        return result;
    }

    inline nlohmann::json generate_disasm_file(const nlohmann::json &args) {
        if (!args.contains("path")) {
            throw std::invalid_argument("Missing required parameter: path");
        }

        std::string path = args["path"];
        ea_t start_ea = args.value("start_ea", inf_get_min_ea());
        ea_t end_ea = args.value("end_ea", inf_get_max_ea());
        int flags = args.value("flags", 0);

        FILE *fp = qfopen(path.c_str(), "w");
        if (!fp) {
            throw std::runtime_error("Failed to open file: " + path);
        }

        gen_file(OFILE_ASM, fp, start_ea, end_ea, flags);
        qfclose(fp);

        nlohmann::json result;
        result["path"] = path;
        result["start_ea"] = static_cast<uint64_t>(start_ea);
        result["end_ea"] = static_cast<uint64_t>(end_ea);
        result["success"] = true;

        return result;
    }

    // ===== Plugin/Processor Info Tools =====

    inline nlohmann::json get_idp_name(const nlohmann::json &args) {
        char buf[256];
        const char *name = ::get_idp_name(buf, sizeof(buf));

        nlohmann::json result;
        result["name"] = name ? name : "";

        return result;
    }

    inline nlohmann::json get_abi_name(const nlohmann::json &args) {
        qstring abi;
        ::get_abi_name(&abi);

        nlohmann::json result;
        result["abi"] = abi.c_str();

        return result;
    }

    inline nlohmann::json get_plugin_options(const nlohmann::json &args) {
        if (!args.contains("plugin_name")) {
            throw std::invalid_argument("Missing required parameter: plugin_name");
        }

        std::string plugin_name_str = args["plugin_name"].get<std::string>();
        const char *opts = ::get_plugin_options(plugin_name_str.c_str());

        nlohmann::json result;
        result["plugin_name"] = plugin_name_str;
        result["options"] = opts ? opts : "";

        return result;
    }

    // ===== Script Execution Tools =====

    inline nlohmann::json execute_idc_script(const nlohmann::json &args) {
        if (!args.contains("script_path")) {
            throw std::invalid_argument("Missing required parameter: script_path");
        }

        std::string script_path = args["script_path"];
        std::string function_name = args.value("function_name", "main");

        qstring errbuf;
        if (!qfileexist(script_path.c_str())) {
            throw std::runtime_error("Script file does not exist: " + script_path);
        }

        // Compile the IDC script
        if (!compile_idc_file(script_path.c_str(), &errbuf)) {
            throw std::runtime_error("Failed to compile IDC script: " + std::string(errbuf.c_str()));
        }

        // Call the specified function
        if (!call_idc_func(nullptr, function_name.c_str(), nullptr, 0, &errbuf)) {
            throw std::runtime_error("Failed to call IDC function '" + function_name + "': " + std::string(errbuf.c_str()));
        }

        nlohmann::json result;
        result["script_path"] = script_path;
        result["function_name"] = function_name;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json execute_python_script(const nlohmann::json &args) {
        if (!args.contains("script_path")) {
            throw std::invalid_argument("Missing required parameter: script_path");
        }

        std::string script_path = args["script_path"];
        std::string script_args = args.value("args", "");

        if (!qfileexist(script_path.c_str())) {
            throw std::runtime_error("Script file does not exist: " + script_path);
        }

        // Get Python extension language
        const char *ext = get_file_ext(script_path.c_str());
        const extlang_object_t el = find_extlang_by_ext(ext);
        if (!el || !el->compile_file) {
            throw std::runtime_error("Python extension not available or file is not a Python script");
        }

        qstring errbuf;

        // If we have arguments, prepend code to set sys.argv
        if (!script_args.empty()) {
            qstrvec_t script_args_vec;
            if (!parse_command_line(&script_args_vec, nullptr, script_args.c_str(), 0)) {
                throw std::runtime_error("Failed to parse script arguments");
            }

            qstring script_code = "import sys\n";
            script_code += qstring("sys.argv = ['") + script_path.c_str() + qstring("']\n");
            for (const auto &arg : script_args_vec) {
                script_code += qstring("sys.argv.append('") + arg + qstring("')\n");
            }

            // Read the script file and prepend our argv setup
            FILE *py_script_file = qfopen(script_path.c_str(), "r");
            if (!py_script_file) {
                throw std::runtime_error("Could not read script file: " + script_path);
            }

            char buf[4096];
            while (true) {
                char *rv = qfgets(buf, sizeof(buf), py_script_file);
                if (rv == nullptr) break;

                size_t line_len = strlen(buf);
                if (line_len > 0 && buf[line_len-1] == '\n') {
                    buf[line_len-1] = 0;
                }

                script_code += qstring(buf) + "\n";
            }
            qfclose(py_script_file);

            if (!el->eval_snippet(script_code.c_str(), &errbuf)) {
                throw std::runtime_error("Failed to execute Python script with arguments: " + std::string(errbuf.c_str()));
            }
        } else {
            // Execute without arguments
            if (!el->compile_file(script_path.c_str(), nullptr, &errbuf)) {
                throw std::runtime_error("Failed to execute Python script: " + std::string(errbuf.c_str()));
            }
        }

        nlohmann::json result;
        result["script_path"] = script_path;
        result["args"] = script_args;
        result["success"] = true;

        return result;
    }

    inline nlohmann::json eval_python_code(const nlohmann::json &args) {
        if (!args.contains("code")) {
            throw std::invalid_argument("Missing required parameter: code");
        }

        std::string code = args["code"];
        std::string script_args = args.value("args", "");

        // Get Python extension language
        const extlang_object_t el = find_extlang_by_ext("py");
        if (!el || !el->eval_snippet) {
            throw std::runtime_error("Python extension not available");
        }

        qstring errbuf;

        // If we have arguments, prepend code to set sys.argv
        if (!script_args.empty()) {
            qstrvec_t script_args_vec;
            if (!parse_command_line(&script_args_vec, nullptr, script_args.c_str(), 0)) {
                throw std::runtime_error("Failed to parse script arguments");
            }

            qstring script_code = "import sys\n";
            script_code += "sys.argv = ['<eval>']\n";
            for (const auto &arg : script_args_vec) {
                script_code += qstring("sys.argv.append('") + arg + qstring("')\n");
            }
            script_code += code.c_str();

            if (!el->eval_snippet(script_code.c_str(), &errbuf)) {
                throw std::runtime_error("Failed to evaluate Python code with arguments: " + std::string(errbuf.c_str()));
            }
        } else {
            if (!el->eval_snippet(code.c_str(), &errbuf)) {
                throw std::runtime_error("Failed to evaluate Python code: " + std::string(errbuf.c_str()));
            }
        }

        nlohmann::json result;
        result["code"] = code;
        result["args"] = script_args;
        result["success"] = true;

        return result;
    }

} // namespace ida_mcp
