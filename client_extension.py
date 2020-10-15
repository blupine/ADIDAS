from idaapi import *
from idautils import *
from idc import *
from jkutils.factor import primesbelow as Primes
from jkutils.graph_hashes import CKoretKaramitasHash
from jkutils.kfuzzy import CKoretFuzzyHashing
from hashlib import md5
from others.tarjan_sort import strongly_connected_components, robust_topological_sort

import json
import requests
import decimal
import difflib
import re
import time

try:
    if IDA_SDK_VERSION < 690:
        # In versions prior to IDA 6.9 PySide is used...
        from PySide import QtGui

        QtWidgets = QtGui
        is_pyqt5 = False
    else:
        # ...while in IDA 6.9, they switched to PyQt5
        from PyQt5 import QtCore, QtGui, QtWidgets

        is_pyqt5 = True
except ImportError:
    pass

opt_ida_subs = bool()
exclude_library_thunk = bool()
use_decompiler_always = True
decompiler_available = True
pseudo_hash = dict()
kfh = CKoretFuzzyHashing()
kfh.bsize = 32

LITTLE_ORANGE = 0x026AFD

class Basic_feature:
    def __init__(self):
        # self.id = int()             # primary key
        self.name = str()  # maxlen 255
        self.address = str()
        self.nodes = int()
        self.edges = int()
        self.indegree = int()
        self.outdegree = int()
        self.size = int()
        self.instructions = int()
        self.mnemonics = str()
        self.names = list()
        self.prototype = str()
        self.cyclomatic_complexity = int()
        self.primes_value = str()
        self.comment = str()
        self.mangled_function = str()
        self.bytes_hash = str()
        self.pseudocode = str()
        self.pseudocode_lines = int()
        self.pseudocode_hash1 = str()
        self.pseudocode_primes = str()
        self.function_flags = int()
        self.assembly = str()
        self.prototype2 = str()
        self.pseudocode_hash2 = str()
        self.pseudocode_hash3 = str()
        self.strongly_connected = int()
        self.loops = int()
        self.rva = str()
        self.tarjan_topological_sort = str()
        self.strongly_connected_spp = str()
        self.clean_assembly = str()
        self.clean_pseudo = str()
        self.mnemonics_spp = str()
        self.switches = str()
        self.function_hash = str()
        self.bytes_sum = int()
        self.md_index = str()
        self.constants = str()
        self.constants_count = int()
        self.segment_rva = str()
        self.assembly_addrs = str()
        self.kgh_hash = str()
        self.binary_name = str()
        self.IsVul = int()

class Program:
    def __init__(self):
        # self.id = int()         # primary key
        self.callgraph_primes = str()
        self.callgraph_all_primes = str()
        self.processor = str()
        self.md5sum = str()

class Program_data:
    def __init__(self):
        # self.id = int()         # primary key
        self.name = str()  # maxlen 255
        self.type = str()  # maxlen 255
        self.value = str()

class Version:
    def __init__(self):
        self.value = str()

class Instructions:
    def __init__(self):
        # self.id = int()        # primary key
        self.address = str()  # unique
        self.disasm = str()
        self.mnemonic = str()
        self.comment1 = str()
        self.comment2 = str()
        self.name = str()
        self.type = str()
        self.pseudocomment = str()
        self.pseudoitp = str()

class Basic_blocks:
    def __init__(self):
        # self.id = int()        # primary key
        self.num = int()
        self.address = str()  # unique

class Bb_relations:
    def __init__(self):
        # self.id = int()        # primary key
        self.parent_id = int()  # not null, references Basic_blocks(id) on delete cascade
        self.child_id = int()  # not null, references Basic_blocks(id) on delete cascade

class Bb_instructions:
    def __init__(self):
        # self.id = int()        # primary key
        self.basic_block_id = int()  # not null, references Functions(id) on delete cascade
        self.instruction_id = int()  # not null, references Instructions(id) on delete cascade

class Function_bblocks:
    def __init__(self):
        # self.id = int()        # primary key
        self.function_id = int()  # not null, references Functions(id) on delete cascade
        self.basic_block_id = int()  # not null, references Basic_blocks(id) on delete cascade

class Callgraph:
    def __init__(self):
        # self.id = int()        # primary key
        self.func_id = int()  # not null, references Functions(id) on delete cascade
        self.address = str()  # not null
        self.type = str()  # not null

class FunctionData:
    def __init__(self):
        self.functions = dict()
        self.program = dict()
        self.program_data = dict()
        self.version = dict()
        self.instruction = dict()
        self.basic_blocks = dict()
        self.bb_relations = dict()
        self.bb_instruction = dict()
        self.function_bblocks = dict()
        self.callgraph = dict()

class CAstVisitor(ctree_visitor_t):
    def __init__(self, cfunc):
        self.primes = Primes(4096)
        ctree_visitor_t.__init__(self, CV_FAST)
        self.cfunc = cfunc
        self.primes_hash = 1
        return

    def visit_expr(self, expr):
        try:
            self.primes_hash *= self.primes[expr.op]
        except:
            traceback.print_exc()
        return 0

    def visit_insn(self, ins):
        try:
            self.primes_hash *= self.primes[ins.op]
        except:
            traceback.print_exc()
        return 0

KERNEL_VERSION = get_kernel_version()

def adidas_decode(ea):
    global KERNEL_VERSION
    if KERNEL_VERSION.startswith("7."):
        ins = idaapi.insn_t()
        decoded_size = idaapi.decode_insn(ins, ea)
        return decoded_size, ins
    elif KERNEL_VERSION.startswith("6."):
        decoded_size = idaapi.decode_insn(ea)
        return decoded_size, idaapi.cmd
    else:
        raise Exception("Unsupported IDA kernel version!")

def is_constant(oper, ea):
    value = oper.value
    # make sure, its not a reference but really constant
    if value in DataRefsFrom(ea):
        return False

    return True

def constant_filter(value):
    """Filter for certain constants/immediate values. Not all values should be
    taken into account for searching. Especially not very small values that
    may just contain the stack frame size.

    @param value: constant value
    @type value: int
    @return: C{True} if value should be included in query. C{False} otherwise
    """
    # no small values
    if value < 0x10000:
        return False

    if value & 0xFFFFFF00 == 0xFFFFFF00 or value & 0xFFFF00 == 0xFFFF00 or \
            value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00 or \
            value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
        return False

    # no single bits sets - mostly defines / flags
    for i in xrange(64):
        if value == (1 << i):
            return False

    return True

def guess_type(ea):
    t = GuessType(ea)
    if not use_decompiler_always:
        return t
    else:
        try:
            ret = decompile_and_get(ea)
            if ret:
                t = ret
        except:
            print("Cannot decompile 0x%x: %s" % (ea, str(sys.exc_info()[1])))
    return t

def decompile_and_get(ea):
    global global_pseudo
    global decompiler_available
    if not decompiler_available:
        return False

    decompiler_plugin = os.getenv("DIAPHORA_DECOMPILER_PLUGIN")
    if decompiler_plugin is None:
        decompiler_plugin = "hexrays"
    if not init_hexrays_plugin() and not (load_plugin(decompiler_plugin) and init_hexrays_plugin()):
        decompiler_available = False
        return False
    f = get_func(ea)
    if f is None:
        return False
    cfunc = decompile(f)
    if cfunc is None:
        # Failed to decompile
        return False
    visitor = CAstVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    pseudo_hash[ea] = visitor.primes_hash

    cmts = idaapi.restore_user_cmts(cfunc.entry_ea)
    if cmts is not None:
        for tl, cmt in cmts.iteritems():
            self.pseudo_comments[tl.ea - self.get_base_address()] = [str(cmt), tl.itp]

    sv = cfunc.get_pseudocode()
    global_pseudo[ea] = []
    first_line = None
    for sline in sv:
        line = tag_remove(sline.line)
        if line.startswith("//"):
            continue

        if first_line is None:
            first_line = line
        else:
            global_pseudo[ea].append(line)
    return first_line

def get_cmp_asm_lines(asm):
    sio = StringIO(asm)
    lines = []
    get_cmp_asm = self.get_cmp_asm
    for line in sio.readlines():
        line = line.strip("\n")
        lines.append(get_cmp_asm(line))
    return "\n".join(lines)


CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
            "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
            "stru_", "dbl_", "locret_"]

def get_cmp_pseudo_lines(pseudo):
    if pseudo is None:
        return pseudo

    # Remove all the comments
    tmp = re_sub(" // .*", "", pseudo)

    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in CMP_REPS:
        tmp = re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
    tmp = re_sub("v[0-9]+", "vXXX", tmp)
    tmp = re_sub("a[0-9]+", "aXXX", tmp)
    tmp = re_sub("arg_[0-9]+", "aXXX", tmp)
    return tmp


re_cache = {}


def re_sub(text, repl, string):
    if text not in re_cache:
        re_cache[text] = re.compile(text, flags=re.IGNORECASE)

    re_obj = re_cache[text]
    return re_obj.sub(repl, string)


def extract_info(functionlist, f_list, selected):
    global primes
    global union_names
    global global_pseudo
    global fun_list
    global bin_dict
    filter = re.compile(("\(vulnerable\)\s?CVE\d+-\d+"))
    index = 1

    again = True
    for f in functionlist:
        t = FunctionData()
        name = GetFunctionName(int(f))
        if selected == True:
            for fname in f_list:
                if fname == name:
                    again = False
            if again == True:
                continue
            else:
                again = True
        true_name = name
        demangled_name = Demangle(name, INF_SHORT_DN)
        if demangled_name == "":
            demangled_name = None

        if demangled_name is not None:
            name = demangled_name
            true_name = name

        f = int(f)
        func = get_func(f)
        if not func:
            print("Cannot get a function object for 0x%x" % f)
            continue

        flow = FlowChart(func)
        size = 0

        # if not opt_ida_subs:
        #     # Unnamed function, ignore it...
        #     if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown") or name.startswith(
        #             "nullsub_"):
        #         continue
        #
        #     # Already recognized runtime's function?
        #     flags = GetFunctionFlags(f)
        #     if flags & FUNC_LIB or flags == -1:
        #         continue
        exclude_library_thunk = True
        if exclude_library_thunk:
            # Skip library and thunk functions
            flags = GetFunctionFlags(f)
            if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
                continue

        image_base = idaapi.get_imagebase()
        nodes = 0
        edges = 0
        instructions = 0
        mnems = []
        dones = {}
        names = list()
        bytes_hash = []
        bytes_sum = 0
        function_hash = []
        outdegree = 0
        indegree = len(list(CodeRefsTo(f, 1)))
        assembly = {}
        basic_blocks_data = {}
        bb_relations = {}
        bb_topo_num = {}
        bb_topological = {}
        switches = []
        bb_degree = {}
        bb_edges = []
        constants = []

        # The callees will be calculated later
        callees = list()
        # Calculate the callers
        callers = list()
        for caller in list(CodeRefsTo(f, 0)):
            caller_func = get_func(caller)
            if caller_func and caller_func.startEA not in callers:
                callers.append(caller_func.startEA)

        mnemonics_spp = 1
        cpu_ins_list = GetInstructionList()
        cpu_ins_list.sort()

        for block in flow:
            if block.endEA == 0 or block.endEA == BADADDR:
                print("0x%08x: Skipping bad basic block" % f)
                continue

            nodes += 1
            instructions_data = []

            block_ea = block.startEA - image_base
            idx = len(bb_topological)
            bb_topological[idx] = []
            bb_topo_num[block_ea] = idx

            for x in list(Heads(block.startEA, block.endEA)):
                mnem = GetMnem(x)
                disasm = GetDisasm(x)
                size += ItemSize(x)
                instructions += 1

                if mnem in cpu_ins_list:
                    mnemonics_spp *= primes[cpu_ins_list.index(mnem)]

                try:
                    assembly[block_ea].append([x - image_base, disasm])
                except KeyError:
                    if nodes == 1:
                        assembly[block_ea] = [[x - image_base, disasm]]
                    else:
                        assembly[block_ea] = [[x - image_base, "loc_%x:" % x], [x - image_base, disasm]]

                decoded_size, ins = adidas_decode(x)
                if ins.Operands[0].type in [o_mem, o_imm, o_far, o_near, o_displ]:
                    decoded_size -= ins.Operands[0].offb
                if ins.Operands[1].type in [o_mem, o_imm, o_far, o_near, o_displ]:
                    decoded_size -= ins.Operands[1].offb
                if decoded_size <= 0:
                    decoded_size = 1

                for oper in ins.Operands:
                    if oper.type == o_imm:
                        if is_constant(oper, x) and constant_filter(oper.value):
                            constants.append(oper.value)

                    drefs = list(DataRefsFrom(x))
                    if len(drefs) > 0:
                        for dref in drefs:
                            if get_func(dref) is None:
                                str_constant = GetString(dref, -1, -1)
                                if str_constant is not None:
                                    if str_constant not in constants:
                                        constants.append(str_constant)

                curr_bytes = GetManyBytes(x, decoded_size, False)
                if curr_bytes is None or len(curr_bytes) != decoded_size:
                    print("Failed to read %d bytes at [%08x]" % (decoded_size, x))
                    continue

                bytes_hash.append(curr_bytes)
                bytes_sum += sum(map(ord, curr_bytes))

                function_hash.append(GetManyBytes(x, ItemSize(x), False))
                outdegree += len(list(CodeRefsFrom(x, 0)))
                mnems.append(mnem)
                op_value = GetOperandValue(x, 1)
                if op_value == -1:
                    op_value = GetOperandValue(x, 0)

                tmp_name = None
                if op_value != BADADDR and op_value in union_names:
                    tmp_name = union_names[op_value]
                    demangled_name = Demangle(tmp_name, INF_SHORT_DN)
                    if demangled_name is not None:
                        tmp_name = demangled_name
                        pos = tmp_name.find("(")
                        if pos > -1:
                            tmp_name = tmp_name[:pos]

                    if not tmp_name.startswith("sub_") and not tmp_name.startswith("nullsub_"):
                        names.append(tmp_name)

                # Calculate the callees
                l = list(CodeRefsFrom(x, 0))
                for callee in l:
                    callee_func = get_func(callee)
                    if callee_func and callee_func.startEA != func.startEA:
                        if callee_func.startEA not in callees:
                            callees.append(callee_func.startEA)

                if len(l) == 0:
                    l = DataRefsFrom(x)

                tmp_type = None
                for ref in l:
                    if ref in union_names:
                        tmp_name = union_names[ref]
                        tmp_type = GetType(ref)

                ins_cmt1 = GetCommentEx(x, 0)
                ins_cmt2 = GetCommentEx(x, 1)
                instructions_data.append([x - image_base, mnem, disasm, ins_cmt1, ins_cmt2, tmp_name, tmp_type])

                switch = get_switch_info_ex(x)
                if switch:
                    switch_cases = switch.get_jtable_size()
                    results = calc_switch_cases(x, switch)

                    if results is not None:
                        # It seems that IDAPython for idaq64 has some bug when reading
                        # switch's cases. Do not attempt to read them if the 'cur_case'
                        # returned object is not iterable.
                        can_iter = False
                        switch_cases_values = set()
                        for idx in xrange(len(results.cases)):
                            cur_case = results.cases[idx]
                            if not '__iter__' in dir(cur_case):
                                break

                            can_iter |= True
                            for cidx in xrange(len(cur_case)):
                                case_id = cur_case[cidx]
                                switch_cases_values.add(case_id)

                        if can_iter:
                            switches.append([switch_cases, list(switch_cases_values)])
        basic_blocks_data[block_ea] = instructions_data
        bb_relations[block_ea] = []
        if block_ea not in bb_degree:
            # bb in degree, out degree
            bb_degree[block_ea] = [0, 0]

        for succ_block in block.succs():
            if succ_block.endEA == 0:
                continue

            succ_base = succ_block.startEA - image_base
            bb_relations[block_ea].append(succ_base)
            bb_degree[block_ea][1] += 1
            bb_edges.append((block_ea, succ_base))
            if succ_base not in bb_degree:
                bb_degree[succ_base] = [0, 0]
            bb_degree[succ_base][0] += 1

            edges += 1
            indegree += 1
            if not dones.has_key(succ_block.id):
                dones[succ_block] = 1

        for pred_block in block.preds():
            if pred_block.endEA == 0:
                continue

            try:
                bb_relations[pred_block.startEA - image_base].append(block.startEA - image_base)
            except KeyError:
                bb_relations[pred_block.startEA - image_base] = [block.startEA - image_base]

            edges += 1
            outdegree += 1
            if not dones.has_key(succ_block.id):
                dones[succ_block] = 1

        for block in flow:
            if block.endEA == 0:
                continue

            block_ea = block.startEA - image_base
            for succ_block in block.succs():
                if succ_block.endEA == 0:
                    continue

                succ_base = succ_block.startEA - image_base
                bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])

        strongly_connected_spp = 0

        try:
            strongly_connected = strongly_connected_components(bb_relations)
            bb_topological_sorted = robust_topological_sort(bb_topological)
            bb_topological = json.dumps(bb_topological_sorted)
            strongly_connected_spp = 1
            for item in strongly_connected:
                val = len(item)
                if val > 1:
                    strongly_connected_spp *= primes[val]
        except:
            # XXX: FIXME: The original implementation that we're using is
            # recursive and can fail. We really need to create our own non
            # recursive version.
            strongly_connected = []
            bb_topological = None

        loops = 0
        for sc in strongly_connected:
            if len(sc) > 1:
                loops += 1
            else:
                if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
                    loops += 1

        asm = []
        keys = assembly.keys()
        keys.sort()

        assembly_addrs = []
        # After sorting our the addresses of basic blocks, be sure that the
        # very first address is always the entry point, no matter at what
        # address it is.
        keys.remove(f - image_base)
        keys.insert(0, f - image_base)
        for key in keys:
            for line in assembly[key]:
                assembly_addrs.append(line[0])
                asm.append(line[1])
        asm = "\n".join(asm)

        cc = edges - nodes + 2
        # -----------------------------------------------------------------
        proto = guess_type(f)
        proto2 = GetType(f)
        try:
            prime = str(primes[cc])
        except:
            print("Cyclomatic complexity too big: 0x%x -> %d" % (f, cc))
            prime = 0

        comment = GetFunctionCmt(f, 1)
        is_vul = 0
        if filter.search(comment):
            is_vul = 1
            comment = re.split("\(vulnerable\)\s*", comment)[1]


        bytes_hash = md5("".join(bytes_hash)).hexdigest()
        function_hash = md5("".join(function_hash)).hexdigest()

        function_flags = GetFunctionFlags(f)
        pseudo = None
        pseudo_hash1 = None
        pseudo_hash2 = None
        pseudo_hash3 = None
        pseudo_lines = 0
        pseudocode_primes = None

        if f in global_pseudo:
            pseudo = "\n".join(global_pseudo[f])
            pseudo_lines = len(global_pseudo[f])
            pseudo_hash1, pseudo_hash2, pseudo_hash3 = kfh.hash_bytes(pseudo).split(";")
            if pseudo_hash1 == "":
                pseudo_hash1 = None
            if pseudo_hash2 == "":
                pseudo_hash2 = None
            if pseudo_hash3 == "":
                pseudo_hash3 = None
            pseudocode_primes = str(pseudo_hash[f])

        try:
            clean_assembly = get_cmp_asm_lines(asm)
        except:
            clean_assembly = ""
            print
            "Error getting assembly for 0x%x" % f

        clean_pseudo = get_cmp_pseudo_lines(pseudo)

        md_index = 0
        if bb_topological:
            bb_topo_order = {}
            for i, scc in enumerate(bb_topological_sorted):
                for bb in scc:
                    bb_topo_order[bb] = i
            tuples = []
            for src, dst in bb_edges:
                tuples.append((
                    bb_topo_order[bb_topo_num[src]],
                    bb_degree[src][0],
                    bb_degree[src][1],
                    bb_degree[dst][0],
                    bb_degree[dst][1],))
            rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
            emb_tuples = (sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
                          for z0, z1, z2, z3, z4 in tuples)
            md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
            md_index = str(md_index)

        seg_rva = x - SegStart(x)

        kgh = CKoretKaramitasHash()
        kgh_hash = kgh.calculate(f)

        rva = f - idaapi.get_imagebase()

        temp = Basic_feature()
        temp.name = name
        temp.mangled_function = true_name
        temp.nodes = nodes
        temp.indegree = indegree
        temp.outdegree = outdegree
        temp.size = size
        temp.instructions = instructions
        temp.mnemonics = mnems
        temp.names = names
        temp.prototype = proto
        temp.constants_count = cc
        temp.primes_value = prime
        temp.address = f
        temp.comment = comment
        temp.bytes_hash = bytes_hash
        temp.pseudocode = pseudo
        temp.pseudocode_lines = pseudo_lines
        temp.pseudocode_hash1 = pseudo_hash1
        temp.pseudocode_primes = pseudocode_primes
        temp.function_flags = function_flags
        temp.assembly = asm
        temp.prototype2 = proto2
        temp.pseudocode_hash2 = pseudo_hash2
        temp.pseudocode_hash3 = pseudo_hash3
        temp.strongly_connected = len(strongly_connected)
        temp.loops = loops
        temp.rva = rva
        temp.function_hash = function_hash
        temp.bytes_sum = bytes_sum
        temp.md_index = md_index
        temp.constants = constants
        temp.constants_count = len(constants)
        temp.segment_rva = seg_rva
        temp.assembly_addrs = assembly_addrs
        temp.kgh_hash = kgh_hash
        temp.is_vul = is_vul
        # temp.is_vul = False
        temp.binary_name = idaapi.get_root_filename()
        t.functions = temp.__dict__

        temp = Program()
        temp.processor = idaapi.get_idp_name()
        t.program = temp.__dict__

        bin_dict[index] = t.__dict__
        index += 1

# 2019.05.20 item = items_with_asm_pseudo
# pseudocode diff
def show_pseudo_diff(item):
    ea1 = str(int(item[1], 16))  # item[1] = ea1
    ea2 = str(int(item[3], 16))  # item[3] = ea2

    # item[13] = pseudo1, item[14] = pseudo2
    if item[13] is None or item[14] is None or len(item[13]) == 0 or len(item[14]) == 0:
        Warning("Sorry, there is no pseudo-code available for either the first or the second database.")
    else:
        html_diff = CHtmlDiff()
        buf1 = item[11] + "\n" + item[13]  # item[11] = proto1, item[13] = pseudo1
        buf2 = item[12] + "\n" + item[14]  # item[12] = proto2, item[14] = pseudo2

        src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

        title = "Diff pseudo-code %s - %s" % (item[2], item[4])  # item[2] = name1, item[4] = name2
        cdiffer = CHtmlViewer()
        cdiffer.Show(src, title)


# 2019.05.21 assembly diff
def prettify_asm(asm_source):
    asm = []
    for line in asm_source.split("\n"):
        if not line.startswith("loc_"):
            asm.append("\t" + line)
        else:
            asm.append(line)
    return "\n".join(asm)


def show_asm_diff(item):
    ea1 = str(int(item[1], 16))  # item[1] = ea1
    ea2 = str(int(item[3], 16))  # item[3] = ea2

    if item[9] is None or item[10] is None or len(item[9]) == 0 or len(item[10]) == 0:
        Warning("Sorry, there is no assembly available for either the first or the second database.")
    else:
        html_diff = CHtmlDiff()
        asm1 = prettify_asm(item[9])
        asm2 = prettify_asm(item[10])
        buf1 = "%s proc near\n%s\n%s endp" % (item[2], asm1, item[2])
        buf2 = "%s proc near\n%s\n%s endp" % (item[4], asm2, item[4])
        src = html_diff.make_file(buf1.split("\n"), buf2.split("\n"))

        title = "Diff assembler %s - %s" % (item[2], item[4])
        cdiffer = CHtmlViewer()
        cdiffer.Show(src, title)

# 2019.05.21 import selected, ea1 from ADIDAS Server
# [0, ea1, name1, ea2, name2, ratio, bb1, bb2, desc, asm1, asm2, proto1, proto2, pseudo1, pseudo2]
def import_one(item):
    # Import just the selected item
    ea1 = str(int(item[1], 16))
    ea2 = str(int(item[3], 16))

    if item[4] is None or len(item[4]) == 0 or item[12] is None or len(item[12]) == 0 or \
            item[14] is None or len(item[14]) == 0:
        Warning("Sorry, target function contains no name or prototype or pseudocode.")

    else:
        proto = item[11]
        name = item[2]
        ea2 = int(ea2)
        if not name.startswith("sub_"):
            if not MakeNameEx(ea2, name, SN_NOWARN | SN_NOCHECK):
                for i in xrange(10):
                    if MakeNameEx(ea2, "%s_%d" % (name, i), SN_NOWARN | SN_NOCHECK):
                        break

        if proto is not None and proto != "int()":
            SetType(ea2, proto)

        item[12] = item[11]
        item[4] = item[2]

    # new_func = self.read_function(str(ea1))
    # self.delete_function(ea1)
    # self.save_function(new_func)

def import_selected(items, selected):
    new_items = []
    for index in selected:
        new_items.append(items[index])
    import_all(new_items)


def import_all(items):
    for item in items:
        import_one(item)

def do_one(item, do_diff, option):
    f_list = list()
    f_list.append(item[0])
    size = len(f_list)
    global primes
    primes = Primes(20000)
    global union_names
    union_names = dict(Names())
    global global_pseudo
    global_pseudo = {}
    global fun_list
    fun_list = list()
    global bin_dict
    bin_dict = dict()
    functionlist = Functions()

    extract_info(functionlist, f_list, True)

    send(do_diff, option, size)

def do_selected(items, selected, do_diff, option):
    f_list = list()
    for index in selected:
        item = items[index]
        f_list.append(item[0])
    size = len(f_list)
    global primes
    primes = Primes(20000)
    global union_names
    union_names = dict(Names())
    global global_pseudo
    global_pseudo = {}
    global fun_list
    fun_list = list()
    global bin_dict
    bin_dict = dict()
    functionlist = Functions()
    extract_info(functionlist, f_list, True)

    send(do_diff, option, size)

def do_all(items, do_diff, option, size):
    f_list = list()
    for item in items:
        f_list.append(item[0])
    global primes
    primes = Primes(20000)
    global union_names
    union_names = dict(Names())
    global global_pseudo
    global_pseudo = {}
    global fun_list
    fun_list = list()
    global bin_dict
    bin_dict = dict()
    functionlist = Functions()
    extract_info(functionlist, f_list, False)

    send(do_diff, option, size)

def send(do_diff, option, size):
    option = str(option)
    data = json.dumps(bin_dict)
    if do_diff is False:
        show_wait_box("HIDECANCEL\n" + "Uploading...\n + It may take a few minutes.")
        start_time = time.time()
        r = requests.post("http://210.107.195.160:8001/upload/features", data=data)
        hide_wait_box()
        #res =
        success, fail = eval(r.text)
        finish_time = str(time.time() - start_time) + " seconds"
        info("Upload Finish!\n"+ "Success / All:     " + str(success) + "/" + str(size) + "\nIt takes " + finish_time)
    else:
        show_wait_box("HIDECANCEL\n" + "Diffing...\n + It may take a few minutes.")
        start_time = time.time()

        d = {}
        d['option'] = option
        d['data'] = data

        for i in range(100):
            try:
                r = requests.post("http://210.107.195.160:8001/upload/diff", data=json.dumps(d))
                if r.status_code == 200:
                    break
            except Exception as e:
                print("connection failed [%d] time.. try again.." % i)
                if i == 99:
                    print("connection failed.. exit...")
                    print e
                    hide_wait_box()
                continue

        hide_wait_box()
        finish_time = str(time.time() - start_time) + " seconds"

        result = eval(r.text)

        best_chooser = CIDAChooser("Best matches")
        partial_chooser = CIDAChooser("Partial matches")
        unreliable_chooser = CIDAChooser("Unreliable matches")
        vulnerable_chooser = CIDAChooser("Vulnerable matches")

        best_chooser.items_with_asm_pseudo = result[0]
        partial_chooser.items_with_asm_pseudo = result[1]
        unreliable_chooser.items_with_asm_pseudo = result[2]
        vulnerable_chooser.items_with_asm_pseudo = result[3]
        match_item = []
        for match_items in result:
            match = []
            for item in match_items:
                match.append(item[:-6])
            match_item.append(match)

        best_chooser.items = match_item[0]
        partial_chooser.items = match_item[1]
        unreliable_chooser.items = match_item[2]
        vulnerable_chooser.items = match_item[3]

        best_chooser.show()
        partial_chooser.show()
        unreliable_chooser.show()
        vulnerable_chooser.show()
        finish_time = str(time.time() - start_time) + " seconds"
        info("Diff Finish!\n" + "It takes " + finish_time)

#####################################################
class CChooser():
    class Item:
        def __init__(self, ea, name, asm1, pseudo1, ea2=None, name2=None, asm2=None, pseudo2=None,
                     desc="100% equal", ratio=0, bb1=0, bb2=0):
            self.ea = ea
            self.vfname = name
            self.asm1 = asm1
            self.pseudo1 = pseudo1
            self.ea2 = ea2
            self.vfname2 = name2
            self.asm2 = asm2
            self.pseudo2 = pseudo2
            self.description = desc
            self.ratio = ratio
            self.bb1 = int(bb1)
            self.bb2 = int(bb2)
            self.cmd_import_selected = None
            self.cmd_import_all = None
            self.cmd_import_all_funcs = None

        def __str__(self):
            return '%08x' % int(self.ea)

    def __init__(self, title, bindiff, show_commands=True):
        if title == "Unmatched in primary":
            self.primary = False
        else:
            self.primary = True

        self.title = title

        self.n = 0
        self.items = []
        self.items_with_asm_pseudo = []

        self.icon = 41
        self.bindiff = bindiff
        self.show_commands = show_commands

        self.cmd_upload_selected = None
        self.cmd_upload_all = None
        self.cmd_diff_selected = None
        self.cmd_diff_all = None

        self.cmd_diff_asm = None
        self.cmd_diff_graph = None
        self.cmd_diff_c = None
        self.cmd_import_selected = None
        self.cmd_import_all = None
        self.cmd_import_all_funcs = None
        self.cmd_show_asm = None
        self.cmd_show_pseudo = None
        self.cmd_highlight_functions = None
        self.cmd_unhighlight_functions = None

        self.selected_items = []

    def add_item(self, item):
        if self.title.startswith("Unmatched in"):
            self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname])
        else:
            self.items.append(["%05lu" % self.n, "%08x" % int(item.ea), item.vfname,
                               "%08x" % int(item.ea2), item.vfname2, "%.3f" % item.ratio,
                               "%d" % item.bb1, "%d" % item.bb2, item.description])
        self.n += 1

    def get_color(self):
        if self.title.startswith("Best"):
            return 0xffff99
        elif self.title.startswith("Partial"):
            return 0x99ff99
        elif self.title.startswith("Unreliable"):
            return 0x9999ff


class CIDAChooser(CChooser, Choose2):

    def __init__(self, title, bindiff=None, show_commands=True):
        CChooser.__init__(self, title, bindiff, show_commands)
        if title.startswith("Unmatched in"):
            Choose2.__init__(self, title, [["Line", 8], ["Address", 8], ["Name", 20]], Choose2.CH_MULTI)
            self.select = False
        elif title.startswith("Select"):
            self.select = True
            self.option = 0
            Choose2.__init__(self, title, [["Function name", 20], ["Segment", 8], ["Start", 8]], Choose2.CH_MULTI)
        else:
            Choose2.__init__(self, title, [["Line", 8], ["Address", 8], ["Name", 20], ["Address 2", 8], ["Name 2", 20],
                                           ["Ratio", 5], ["BBlocks 1", 5], ["BBlocks 2", 5], ["Description", 30]],
                             Choose2.CH_MULTI)
            self.select = False

    def OnClose(self):
        """space holder"""
        return True

    def OnEditLine(self, n):
        """space holder"""

    def OnInsertLine(self):
        pass

    def OnSelectLine(self, n):
        item = self.items[int(n)]
        if self.primary:
            try:
                jump_ea = int(item[1], 16)
                # Only jump for valid addresses
                if isEnabled(jump_ea):
                    jumpto(jump_ea)
            except:
                print
                "OnSelectLine", sys.exc_info()[1]
        else:
            self.bindiff.show_asm(self.items[n], self.primary)

    def OnGetLine(self, n):
        try:
            return self.items[n]
        except:
            print
            "OnGetLine", sys.exc_info()[1]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        if n >= 0:
            del self.items[n]
        return True

    def OnRefresh(self, n):
        return n

    def show(self, force=False):
        self.show_commands = True
        # if self.show_commands:
        # remove assembly, pseudocode from items
        # items[9] = assembly f, items[10] = assembly df, items[11] = pseudocode f, items[12] = pseudocode df
        # self.items = sorted(self.items, key=lambda x: decimal.Decimal(x[5]), reverse=True)

        t = self.Show()
        if t < 0:
            return False
        if self.select is True:
            self.cmd_upload_selected = self.AddCommand("Upload selected")
            self.cmd_upload_all = self.AddCommand("Upload *all* functions")
            self.cmd_diff_selected = self.AddCommand("Diff selected")
            self.cmd_diff_all = self.AddCommand("Diff *all*")
        elif self.show_commands and (self.cmd_diff_asm is None or force):
            # create aditional actions handlers
            self.cmd_diff_asm = self.AddCommand("Diff assembly")
            self.cmd_diff_c = self.AddCommand("Diff pseudo-code")
            self.cmd_diff_graph = self.AddCommand("Diff assembly in a graph")
            self.cmd_import_selected = self.AddCommand("Import selected")
            self.cmd_import_selected_auto = self.AddCommand("Import selected sub_*")
            self.cmd_import_all = self.AddCommand("Import *all* functions")
            self.cmd_import_all_funcs = self.AddCommand("Import *all* data for sub_* functions")
            self.cmd_highlight_functions = self.AddCommand("Highlight matches")
            self.cmd_unhighlight_functions = self.AddCommand("Unhighlight matches")
            self.cmd_save_results = self.AddCommand("Save diffing results")
        elif not self.show_commands and (self.cmd_show_asm is None or force):
            self.cmd_show_asm = self.AddCommand("Show assembly")
            self.cmd_show_pseudo = self.AddCommand("Show pseudo-code")

        return True

    def OnCommand(self, n, cmd_id):
        # Aditional right-click-menu commands handles

        if self.select is True:
            if cmd_id == self.cmd_upload_selected:
                if len(self.selected_items) <= 1:
                    do_one(self.items[n], False, self.option)
                else:
                    if askyn_c(1, "HIDECANCEL\nDo you really want to upload all selected functions?") == 1:
                        do_selected(self.items, self.selected_items, False, self.option)
            elif cmd_id == self.cmd_upload_all:
                if askyn_c(1,
                           "HIDECANCEL\nDo you really want to upload all functions?") == 1:
                    do_all(self.items, False, self.option, len(self.items))
            elif cmd_id == self.cmd_diff_selected:
                if len(self.selected_items) <= 1:
                    do_one(self.items[n], True, self.option)
                else:
                    if askyn_c(1, "HIDECANCEL\nDo you really want to diff all selected functions?") == 1:
                        do_selected(self.items, self.selected_items, True, self.option)
            elif cmd_id == self.cmd_diff_all:
                if askyn_c(1,
                           "HIDECANCEL\nDo you really want to diff all functions?") == 1:
                    do_all(self.items, True, self.option, len(self.items))
            return True
        if cmd_id == self.cmd_show_asm:
            self.bindiff.show_asm(self.items[n], self.primary)
        elif cmd_id == self.cmd_show_pseudo:
            self.bindiff.show_pseudo(self.items[n], self.primary)
        elif cmd_id == self.cmd_import_all or cmd_id == self.cmd_import_all_funcs:
            if askyn_c(1,
                       "HIDECANCEL\nDo you really want to import all matched functions, comments, prototypes and definitions?") == 1:
                import_all(self.items_with_asm_pseudo)
        elif cmd_id == self.cmd_import_selected or cmd_id == self.cmd_import_selected_auto:
            if len(self.selected_items) <= 1:
                import_one(self.items_with_asm_pseudo[n])
                # self.bindiff.import_one(self.items[n])
            else:
                if askyn_c(1,
                           "HIDECANCEL\nDo you really want to import all selected IDA named matched functions, comments, prototypes and definitions?") == 1:
                    import_selected(self.items_with_asm_pseudo, self.selected_items)
        elif cmd_id == self.cmd_diff_c:
            show_pseudo_diff(self.items_with_asm_pseudo[n])
            # self.bindiff.show_pseudo_diff(self.items[n])
        elif cmd_id == self.cmd_diff_asm:
            show_asm_diff(self.items_with_asm_pseudo[n])
            # self.bindiff.show_asm_diff(self.items[n])
        elif cmd_id == self.cmd_highlight_functions:
            if askyn_c(1, "HIDECANCEL\nDo you want to change the background color of each matched function?") == 1:
                color = self.get_color()
                for item in self.items:
                    ea = int(item[1], 16)
                    if not SetColor(ea, CIC_FUNC, color):
                        print
                        "Error setting color for %x" % ea
                Refresh()
        elif cmd_id == self.cmd_unhighlight_functions:
            for item in self.items:
                ea = int(item[1], 16)
                if not SetColor(ea, CIC_FUNC, 0xFFFFFF):
                    print
                    "Error setting color for %x" % ea
            Refresh()
        elif cmd_id == self.cmd_diff_graph:
            item = self.items[n]
            ea1 = int(item[1], 16)
            name1 = item[2]
            ea2 = int(item[3], 16)
            name2 = item[4]
            log("Diff graph for 0x%x - 0x%x" % (ea1, ea2))
            self.bindiff.graph_diff(ea1, name1, ea2, name2)
        elif cmd_id == self.cmd_save_results:
            filename = AskFile(1, "*.diaphora", "Select the file to store diffing results")
            if filename is not None:
                self.bindiff.save_results(filename)
        return True

    def OnSelectionChange(self, sel_list):
        self.selected_items = sel_list

    def seems_false_positive(self, item):
        if not item[2].startswith("sub_") and not item[4].startswith("sub_"):
            if item[2] != item[4]:
                if item[4].find(item[2]) == -1 and not item[2].find(item[4]) == -1:
                    return True

        return False

    def OnGetLineAttr(self, n):
        if self.title.startswith("Vulnerable"):
            color = int("0x%02x%02x%02x" % (153, 51, 255), 16)
            return [color, 0]
        if not self.title.startswith("Unmatched") and self.select is False:
            item = self.items[n]
            ratio = float(item[5])
            if self.seems_false_positive(item):
                return [LITTLE_ORANGE, 0]
            else:
                red = int(164 * (1 - ratio))
                green = int(128 * ratio)
                blue = int(255 * (1 - ratio))
                color = int("0x%02x%02x%02x" % (blue, green, red), 16)
            return [color, 0]
        return [0xFFFFFF, 0]

    def create_choosers(self):
        self.select_chooser = self.chooser("Select", self)
        self.unreliable_chooser = self.chooser("Unreliable matches", self)
        self.partial_chooser = self.chooser("Partial matches", self)
        self.best_chooser = self.chooser("Best matches", self)

        self.unmatched_second = self.chooser("Unmatched in secondary", self, False)
        self.unmatched_primary = self.chooser("Unmatched in primary", self, False)


class CIdaMenuHandlerShowChoosers(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        show_choosers()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------
class CIdaMenuHandlerSaveResults(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        save_results()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------
class CIdaMenuHandlerLoadResults(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        load_results()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def register_menu_action(action_name, action_desc, handler, hotkey=None):
    show_choosers_action = idaapi.action_desc_t(
        action_name,
        action_desc,
        handler,
        hotkey,
        None,
        -1)
    idaapi.register_action(show_choosers_action)
    idaapi.attach_action_to_menu(
        'Edit/Plugins/%s' % action_desc,
        action_name,
        idaapi.SETMENU_APP)


def register_menu():
    menu_items = [
        ['diaphora:show_results', 'Diaphora - Show results', CIdaMenuHandlerShowChoosers(), "F3"],
        ['diaphora:save_results', 'Diaphora - Save results', CIdaMenuHandlerSaveResults(), None],
        ['diaphora:load_results', 'Diaphora - Load results', CIdaMenuHandlerLoadResults(), None]
    ]
    for item in menu_items:
        action_name, action_desc, action_handler, hotkey = item
        register_menu_action(action_name, action_desc, action_handler, hotkey)

    Warning("""AUTOHIDE REGISTRY\nIf you close one tab you can always re-open it by pressing F3
or selecting Edit -> Plugins -> Diaphora - Show results""")


#####################################################
class CHtmlViewer(PluginForm):
    def OnCreate(self, form):
        if is_pyqt5:
            self.parent = self.FormToPyQtWidget(form)
        else:
            self.parent = self.FormToPySideWidget(form)
        self.PopulateForm()

        self.browser = None
        self.layout = None
        return 1

    def PopulateForm(self):
        self.layout = QtWidgets.QVBoxLayout()
        self.browser = QtWidgets.QTextBrowser()
        self.browser.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.browser.setHtml(self.text)
        self.browser.setReadOnly(True)
        self.browser.setFontWeight(12)
        self.layout.addWidget(self.browser)
        self.parent.setLayout(self.layout)

    def Show(self, text, title):
        self.text = text
        return PluginForm.Show(self, title)


# -----------------------------------------------------------------------
class CHtmlDiff:
    """A replacement for difflib.HtmlDiff that tries to enforce a max width

    The main challenge is to do this given QTextBrowser's limitations. In
    particular, QTextBrowser only implements a minimum of CSS.
    """

    _html_template = """
  <html>
  <head>
  <style>%(style)s</style>
  </head>
  <body>
  <table class="diff_tab" cellspacing=0>
  %(rows)s
  </table>
  </body>
  </html>
  """

    _style = """
  table.diff_tab {
    font-family: Courier, monospace;
    table-layout: fixed;
    width: 100%;
  }
  table td {
    white-space: nowrap;
    overflow: hidden;
  }

  .diff_add {
    background-color: #aaffaa;
  }
  .diff_chg {
    background-color: #ffff77;
  }
  .diff_sub {
    background-color: #ffaaaa;
  }
  .diff_lineno {
    text-align: right;
    background-color: #e0e0e0;
  }
  """

    _row_template = """
  <tr>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
      <td class="diff_lineno" width="auto">%s</td>
      <td class="diff_play" nowrap width="45%%">%s</td>
  </tr>
  """

    _rexp_too_much_space = re.compile("^\t[.\\w]+ {8}")

    def make_file(self, lhs, rhs):
        rows = []
        for left, right, changed in difflib._mdiff(lhs, rhs):
            lno, ltxt = left
            rno, rtxt = right
            ltxt = self._stop_wasting_space(ltxt)
            rtxt = self._stop_wasting_space(rtxt)
            ltxt = self._trunc(ltxt, changed).replace(" ", "&nbsp;")
            rtxt = self._trunc(rtxt, changed).replace(" ", "&nbsp;")
            row = self._row_template % (str(lno), ltxt, str(rno), rtxt)
            rows.append(row)

        all_the_rows = "\n".join(rows)
        all_the_rows = all_the_rows.replace(
            "\x00+", '<span class="diff_add">').replace(
            "\x00-", '<span class="diff_sub">').replace(
            "\x00^", '<span class="diff_chg">').replace(
            "\x01", '</span>').replace(
            "\t", 4 * "&nbsp;")

        res = self._html_template % {"style": self._style, "rows": all_the_rows}
        return res

    def _stop_wasting_space(self, s):
        """I never understood why you'd want to have 13 spaces between instruction and args'
        """
        m = self._rexp_too_much_space.search(s)
        if m:
            mlen = len(m.group(0))
            return s[:mlen - 4] + s[mlen:]
        else:
            return s

    def _trunc(self, s, changed, max_col=120):
        if not changed:
            return s[:max_col]

        # Don't count markup towards the length.
        outlen = 0
        push = 0
        for i, ch in enumerate(s):
            if ch == "\x00":  # Followed by an additional byte that should also not count
                outlen -= 1
                push = True
            elif ch == "\x01":
                push = False
            else:
                outlen += 1
            if outlen == max_col:
                break

        res = s[:i + 1]
        if push:
            res += "\x01"

        return res

# -----------------------------------------------------------------------
class GUIForm(Form):
    def __init__(self):
        self.invert = False
        self.option = 7
        Form.__init__(self, r"""ADIDAS

        {FormChangeCb}
        Welcome to ADIDAS.
        ADIDAS allows you to Upload or Diff a function of your choice.
        Below you can choose the Heuristic you want. 
        Press OK to start.

          Heuristics
          <Best matches:{cBest}>
          <Partial matches:{cPartial}>
          <Unreliable matches:{cUnreliable}>{cGroup}>""", {
            'cGroup': Form.ChkGroupControl(("cBest", "cPartial", "cUnreliable")),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange)})

    def OnFormChange(self, fid):
        self.option = self.GetControlValue(self.cGroup)
        # if fid == self.cGroup1.id:
        #     self.option = self.GetControlValue(self.cGroup1)
        return 1
    # 0: None
    # 1: Only Best matches
    # 2: Only Partial matches
    # 3: Best + Partial
    # 4: Only Unreliable matches
    # 5: Best + Unreliable
    # 6: Partial + Unreliable
    # 7: ALL

if __name__ == '__main__':
    # GUI upload
    f = GUIForm()
    f.Compile()
    f.cBest.checked = True
    f.cPartial.checked = True
    f.cUnreliable.checked = True

    ok = f.Execute()
    if ok == 1:
        select_chooser = CIDAChooser("Select")
        select_chooser.option = f.option
        select_items = list()
        functionlist = Functions()
        for f in functionlist:
            my_item = list()
            my_item.append(GetFunctionName(int(f)))
            my_item.append(SegName(int(f)))
            my_item.append(str(hex(f)).zfill(6))
            select_items.append(my_item)
        select_chooser.items = select_items
        select_chooser.show()
        info("Select your functions")

#  When bong's socket finish, these will be used
    # import time
    # t = 1
    # while(t <= 3):
    #     text = "time: " + str(t) + " seconds"
    #     show_wait_box("HIDECANCEL\n" + text)
    #     time.sleep(1)
    #     hide_wait_box()
    #     t += 1
    # hide_wait_box()
    # info("finish!")