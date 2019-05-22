import MySQLdb
import time
import re
import threading
from difflib import SequenceMatcher
#from cStringIO import StringIO
from io import StringIO

CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
            "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
            "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]

# sorting dictionary for inserting sql
FUNC_ATTR = ["name", "address", "nodes", "edges", "indegree", "outdegree",
        "size", "instructions","mnemonics", "names","prototype", "cyclomatic_complexity",
        "primes_value",  "comment", "mangled_function", "bytes_hash", "pseudocode",
        "pseudocode_lines", "pseudocode_hash1", "pseudocode_primes", "function_flags",
        "assembly", "prototype2", "pseudocode_hash2", "pseudocode_hash3", "strongly_connected",
        "loops", "rva", "tarjan_topological_sort", "strongly_connected_spp",
        "clean_assembly", "clean_pseudo", "mnemonics_spp", "switches", "function_hash",
        "bytes_sum", "md_index", "constants", "constants_count", "segment_rva",
        "assembly_addrs","kgh_hash", "binary_name", "is_vul"]

# 2019.05.05
def log(msg):
  #if isinstance(threading.current_thread(), threading._MainThread):
    print("[%s] %s\n" % (time.asctime(), msg))

def log_refresh(msg, show=False, do_log=True):
    log(msg)

# -----------------------------------------------------------------------
def quick_ratio(buf1, buf2):
    try:
        if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
            return 0
        s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
        return s.quick_ratio()
    except Exception as e:
        print(e)
        #"quick_ratio:", str(sys.exc_info()[1])
        return 0

# -----------------------------------------------------------------------
def real_quick_ratio(buf1, buf2):
    try:
        if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
            return 0
        s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
        return s.real_quick_ratio()
    except:
        print
        #"real_quick_ratio:", str(sys.exc_info()[1])
        return 0

class CChooser():
    class Item:
        def __init__(self, ea, name, asm1, proto1, pseudo1, ea2=None, name2=None, asm2=None, proto2=None, pseudo2=None,
                     desc="100% equal", ratio=0, bb1=0, bb2=0):
            self.ea = ea
            self.vfname = name
            self.asm1 = asm1
            self.proto1 = proto1
            self.pseudo1 = pseudo1
            self.ea2 = ea2
            self.vfname2 = name2
            self.asm2 = asm2
            self.proto2 = proto2
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
        self.icon = 41
        self.bindiff = bindiff
        self.show_commands = show_commands

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
							   "%d" % item.bb1, "%d" % item.bb2, item.description,
                               item.asm1, item.asm2, item.proto1, item.proto2, item.pseudo1, item.pseudo2])
        self.n += 1
    # [0, ea1, name1, ea2, name2, ratio, bb1, bb2, desc, asm1, asm2, proto1, proto2, pseudo1, pseudo2]

    def get_color(self):
        if self.title.startswith("Best"):
            return 0xffff99
        elif self.title.startswith("Partial"):
            return 0x99ff99
        elif self.title.startswith("Unreliable"):
            return 0x9999ff

MAX_PROCESSED_ROWS = 1000000
TIMEOUT_LIMIT = 60 * 3

class ADiff:
    def __init__(self, option=None, chooser=CChooser):
        self.db_name = 'ADIDAS'
        self.conn = None
        self.open_db()
        self.matched1 = set()
        self.matched2 = set()
        self.total_functions1 = None
        self.total_functions2 = None

        self.relaxed_ratio = False
        self.experimental = False
        self.slow_heuristics = False

        self.chooser = chooser
        self.create_choosers()

        self.re_cache = {}

        # 2019.05.22 best heuristics?
        self.best_heuristics = False
        # 2019.05.22 partial heuristics?
        self.partial_heuristics = False
        # Use unreliable heuristics?
        self.unreliable_heuristics = False

        self.set_option(option)
        ####################################################################
        # LIMITS
        #
        # Do not run heuristics for more than 3 minutes per each 20.000
        # functions.

        #self.timeout = TIMEOUT_LIMIT
        # It's typical in SQL queries to get a cartesian product of the
        # results in the functions tables. Do not process more than this
        # value per each 20k functions.
        #self.max_processed_rows = MAX_PROCESSED_ROWS
        # Limits to filter the functions to export
        self.min_ea = 0
        self.max_ea = 0
        # Export only non IDA automatically generated function names? I.e.,
        # excluding these starting with sub_*
        self.ida_subs = True
        # Export only function summaries instead of also exporting both the
        # basic blocks and all instructions used by functions?
        self.function_summaries_only = False
        # Ignore IDA's automatically generated sub_* names for heuristics
        # like the 'Same name'?
        self.ignore_sub_names = True
        # Ignore any and all function names for the 'Same name' heuristic?
        self.ignore_all_names = True
        # Ignore small functions?
        self.ignore_small_functions = False
        self.max_processed_rows = MAX_PROCESSED_ROWS
        self.timeout = TIMEOUT_LIMIT



        ####################################################################
    def set_option(self, option):
        opt = int(option)
        if opt == 0:
            pass# default all none
        if opt in [1, 3, 5, 7]:
            self.best_heuristics = True
        if opt in [2, 3, 6, 7]:
            self.partial_heuristics = True
        if opt in [4, 5, 6, 7]:
            self.unreliable_heuristics = True

        # 0: None
        # 1: Only Best matches
        # 2: Only Partial matches
        # 3: Best + Partial
        # 4: Only Unreliable matches
        # 5: Best + Unreliable
        # 6: Partial + Unreliable
        # 7: ALL


    def open_db(self):
        self.conn = MySQLdb.connect(host='127.0.0.1', port=3306, user='root', passwd='dviis518', db=self.db_name)

    def close_db(self):
        self.conn.close()

    def db_cursor(self):
        cursor = self.conn.cursor(MySQLdb.cursors.DictCursor)
        return cursor
        #return self.conn.cursor()

    def create_choosers(self):
        self.unreliable_chooser = self.chooser("Unreliable matches", self)
        self.partial_chooser = self.chooser("Partial matches", self)
        self.best_chooser = self.chooser("Best matches", self)

        self.unmatched_second = self.chooser("Unmatched in secondary", self, False)
        self.unmatched_primary = self.chooser("Unmatched in primary", self, False)

    def re_sub(self, text, repl, string):
        if text not in self.re_cache:
            self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

        re_obj = self.re_cache[text]
        return re_obj.sub(repl, string)

    def get_cmp_asm_lines(self, asm):
        #sio = io.StriongIO(asm)
        sio = StringIO(asm)
        lines = []
        get_cmp_asm = self.get_cmp_asm
        for line in sio.readlines():
            line = line.strip("\n")
            lines.append(get_cmp_asm(line))
        return "\n".join(lines)

    def get_cmp_pseudo_lines(self, pseudo):
        if pseudo is None:
            return pseudo

        # Remove all the comments
        tmp = self.re_sub(" // .*", "", pseudo)

        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
        tmp = self.re_sub("v[0-9]+", "vXXX", tmp)
        tmp = self.re_sub("a[0-9]+", "aXXX", tmp)
        tmp = self.re_sub("arg_[0-9]+", "aXXX", tmp)
        return tmp

    def get_cmp_asm(self, asm):
        if asm is None:
            return asm

        # Ignore the comments in the assembly dump
        tmp = asm.split(";")[0]
        tmp = tmp.split(" # ")[0]
        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

        # Remove dword ptr, byte ptr, etc...
        for rep in CMP_REMS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "", tmp)

        reps = ["\+[a-f0-9A-F]+h\+"]
        for rep in reps:
            tmp = self.re_sub(rep, "+XXXX+", tmp)
        tmp = self.re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)

        # Strip any possible remaining white-space character at the end of
        # the cleaned-up instruction
        tmp = self.re_sub("[ \t\n]+$", "", tmp)

        # Replace aName_XXX with aXXX, useful to ignore small changes in
        # offsets created to strings
        tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)
        return tmp



    def diff(self, data):
        cur = self.db_cursor()
        arch = self.get_arch_from_data(data)
        if arch == -1:
            print("invalid processor type.")
            return -1

        table = "upload_" + arch + "_functions"
        table2 = self.create_temp_db(data)

        try:
            t0 = time.time()

            #log_refresh("Diffing...", True)

            self.do_continue = True

            if self.do_continue:
                # Compare the call graphs
                #self.check_callgraph()

                # Find the unmodified functions
                #log_refresh("Finding best matches...")
                #self.find_equal_matches_parallel(table, data)
                self.find_equal_matches(table, table2)

                self.find_matches(table, table2)
                """
                # Find the modified functions
                #log_refresh("Finding partial matches")
                self.find_matches_parallel()

                if self.slow_heuristics:
                    # Find the functions from the callgraph
                    #log_refresh("Finding with heuristic 'Callgraph matches'")
                    self.find_callgraph_matches()

                if self.unreliable:
                    # Find using likely unreliable methods modified functions
                    #log_refresh("Finding probably unreliable matches")
                    self.find_unreliable_matches()

                if self.experimental:
                    # Find using experimental methods modified functions
                    #log_refresh("Finding experimental matches")
                    self.find_experimental_matches()

                # Show the list of unmatched functions in both databases
                #log_refresh("Finding unmatched functions")
                self.find_unmatched()
                """
                #log("Done. Took {} seconds".format(time.time() - t0))
        finally:
            cur.execute("DROP TABLE `%s`" % table2)
            cur.close()
            # drop temp table

        #print(self.best_chooser.items)
        return self.best_chooser.items, self.partial_chooser.items, self.unreliable_chooser.items

    def find_equal_matches(self, table, table2):
        cur = self.db_cursor()

        sql = """select count(*) as total from `%s` union all select count(*) as total from `%s`""" %(table, table2)
        cur.execute(sql)
        rows = cur.fetchall()
        if len(rows) != 2:
            Warning("Malformed database, only %d rows!" % len(rows))
            raise Exception("Malformed database!")

        # self.total_functions1 = rows[0][0]
        # self.total_functions2 = rows[1][0]
        self.total_functions1 = rows[0]["total"]
        self.total_functions2 = rows[1]["total"]
        postfix = ""
        if self.best_heuristics:
            sql = """SELECT t1.address AS ea, t1.mangled_function, t1.nodes
                    FROM """ + table + """ AS t1
                    INNER JOIN `""" + table2 + """` AS t2 
                    ON (
                        t1.name = t2.name AND
                        t1.address = t2.address AND
                        t1.nodes = t2.nodes AND
                        t1.edges = t2.edges AND
                        t1.indegree = t2.indegree AND
                        t1.outdegree = t2.outdegree AND
                        t1.instructions = t2.instructions AND
                        t1.mnemonics = t2.mnemonics AND
                        t1.names = t2.names AND
                        t1.prototype = t2.prototype AND
                        t1.cyclomatic_complexity = t2.cyclomatic_complexity AND
                        t1.primes_value = t2.primes_value AND
                        t1.comment = t2.comment AND
                        t1.mangled_function = t2.mangled_function AND
                        t1.bytes_hash = t2.bytes_hash AND
                        t1.pseudocode = t2.pseudocode AND
                        t1.pseudocode_lines = t2.pseudocode_lines AND
                        t1.pseudocode_hash1 = t2.pseudocode_hash1 AND
                        t1.pseudocode_primes = t2.pseudocode_primes AND
                        t1.function_flags = t2.function_flags AND
                        t1.assembly = t2.assembly AND
                        t1.prototype2 = t2.prototype2 AND
                        t1.pseudocode_hash2 = t2.pseudocode_hash2 AND
                        t1.pseudocode_hash3 = t2.pseudocode_hash3 AND
                        t1.strongly_connected = t2.strongly_connected AND
                        t1.loops = t2.loops AND
                        t1.rva = t2.rva AND
                        t1.tarjan_topological_sort = t2.tarjan_topological_sort AND
                        t1.strongly_connected_spp = t2.strongly_connected_spp AND
                        t1.clean_assembly = t2.clean_assembly AND
                        t1.clean_pseudo = t2.clean_pseudo AND
                        t1.mnemonics_spp = t2.mnemonics_spp AND
                        t1.switches = t2.switches AND
                        t1.function_hash = t2.function_hash AND
                        t1.bytes_sum = t2.bytes_sum AND
                        t1.md_index = t2.md_index AND
                        t1.constants = t2.constants AND
                        t1.constants_count = t2.constants_count AND
                        t1.segment_rva = t2.segment_rva AND
                        t1.assembly_addrs = t2.assembly_addrs AND
                        t1.kgh_hash = t2.kgh_hash AND
                        t1.binary_name = t2.binary_name AND
                        t1.is_vul = t2.is_vul 
                        )"""
            cur.execute(sql)
            rows = cur.fetchall()
            choose = self.best_chooser
            if len(rows) > 0:
                for row in rows:
                    name = row["mangled_function"]
                    ea = row["ea"]
                    nodes = int(row["nodes"])
                    proto = row["prototype"]
                    asm = row["assembly"]
                    pseudo = row["pseudocode"]
                    choose.add_item(CChooser.Item(ea, name, asm, proto, pseudo, ea, name, asm, proto, pseudo, "100% equal", 1, nodes, nodes))
                    self.matched1.add(name)
                    self.matched2.add(name)

            if self.ignore_small_functions:
              postfix = " and f.instructions > 5 and df.instructions > 5 "

            # 2019.05.20 add asm, pseudocode on item, to implement asm diff, pseudocode diff
            sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Same RVA and hash' description,
                            f.nodes bb1, df.nodes bb2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE (df.rva = f.rva
                            OR df.segment_rva = f.segment_rva)
                            AND df.bytes_hash = f.bytes_hash
                            AND df.instructions = f.instructions
                            AND ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                            OR (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))"""
            log_refresh("Finding with heuristic 'Same RVA and hash'")
            self.add_matches_from_query(sql, choose)

            sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Same order and hash' description,
                            f.nodes bb1, df.nodes bb2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE df.id = f.id
                            AND df.bytes_hash = f.bytes_hash
                            AND df.instructions = f.instructions
                            AND ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                            OR (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))
                            AND ((f.nodes > 1 and df.nodes > 1
                            AND f.instructions > 5 and df.instructions > 5)
                            OR f.instructions > 10 and df.instructions > 10)"""
            log_refresh("Finding with heuristic 'Same order and hash'")
            self.add_matches_from_query(sql, choose)

            sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Function hash' description,
                            f.nodes bb1, df.nodes bb2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.function_hash = df.function_hash 
                            AND ((f.nodes > 1 and df.nodes > 1
                            AND f.instructions > 5 and df.instructions > 5)
                            OR f.instructions > 10 and df.instructions > 10)"""
            log_refresh("Finding with heuristic 'Function hash'")
            self.add_matches_from_query(sql, choose)

            sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Bytes hash and names' description,
                            f.nodes bb1, df.nodes bb2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.bytes_hash = df.bytes_hash
                            AND f.names = df.names
                            AND f.names != '[]'
                            AND f.instructions > 5 and df.instructions > 5"""
            log_refresh("Finding with heuristic 'Bytes hash and names'")
            self.add_matches_from_query(sql, choose)

            #cast(f.md_index as float) md1, cast(df.md_index as float) md2

            sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Bytes hash' description,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.bytes_hash = df.bytes_hash
                            AND f.instructions > 5 and df.instructions > 5"""
            log_refresh("Finding with heuristic 'Bytes hash'")
            self.add_matches_from_query(sql, choose)

            #if not self.ignore_all_names:
            #    self.find_same_name(self.partial_chooser)
            if self.unreliable_heuristics:
            #if self.unreliable:
                sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                            'Bytes sum' description,
                            f.nodes bb1, df.nodes bb2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.bytes_sum = df.bytes_sum
                            AND f.size = df.size
                            AND f.mnemonics = df.mnemonics
                            AND f.instructions > 5 and df.instructions > 5"""
                log_refresh("Finding with heuristic 'Bytes sum'")
                self.add_matches_from_query(sql, choose)

            sql = """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal pseudo-code' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.pseudocode = df.pseudocode
                            AND df.pseudocode is not null
                            AND f.pseudocode_lines >= 5 """ + postfix + """
                            AND f.name not like 'nullsub%'
                            AND df.name not like 'nullsub%'
                        UNION
                        SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal assembly' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.assembly = df.assembly
                            AND df.assembly is not null
                            AND f.instructions >= 4 and df.instructions >= 4
                            AND f.name not like 'nullsub%'
                            AND df.name not like 'nullsub%' """
            log_refresh("Finding with heuristic 'Equal assembly or pseudo-code'")
            self.add_matches_from_query(sql, choose)

        sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Same cleaned up assembly or pseudo-code' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f, 
                            `""" + table2 + """` df
                    WHERE (f.clean_assembly = df.clean_assembly
                        OR f.clean_pseudo = df.clean_pseudo) 
                        AND f.pseudocode_lines > 5 and df.pseudocode_lines > 5
                        AND f.name not like 'nullsub%'
                        AND df.name not like 'nullsub%' """
        log_refresh("Finding with heuristic 'Same cleaned up assembly or pseudo-code'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same address, nodes, edges and mnemonics' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.rva = df.rva
                        AND f.instructions = df.instructions
                        AND f.nodes = df.nodes
                        AND f.edges = df.edges
                        AND f.mnemonics = df.mnemonics""" + postfix
        log_refresh("Finding with heuristic 'Same address, nodes, edges and mnemonics'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, None)

        cur.close()

    def find_matches(self, table, table2):
        print("###################################################")
        print(table)
        print(table2)

        choose = self.partial_chooser

        postfix = ""
        if self.ignore_small_functions:
            postfix = " AND f.instructions > 5 and df.instructions > 5 "

        sql = """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare KOKA hash' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                (SELECT kgh_hash
                    FROM diff.functions
                    WHERE kgh_hash != 0
                    GROUP BY kgh_hash
                    HAVING COUNT(*) <= 2
                UNION 
                SELECT kgh_hash
                    FROM main.functions
                    WHERE kgh_hash != 0
                    GROUP BY kgh_hash
                    HAVING COUNT(*) <= 2
                ) shared_hashes
                WHERE f.kgh_hash = df.kgh_hash
                AND df.kgh_hash = shared_hashes.kgh_hash
                AND f.nodes > 3 """ + postfix
        log_refresh("Finding with heuristic 'Same rare KOKA hash'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

        sql = """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare MD Index' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                (SELECT md_index
                    FROM diff.functions
                    WHERE md_index != 0
                    GROUP BY md_index
                    HAVING COUNT(*) <= 2
                UNION 
                SELECT md_index
                    FROM main.functions
                    WHERE md_index != 0
                    GROUP BY md_index
                    HAVING COUNT(*) <= 2
                ) shared_mds
                WHERE f.md_index = df.md_index
                AND df.md_index = shared_mds.md_index
                AND f.nodes > 10 """ + postfix
        log_refresh("Finding with heuristic 'Same rare MD Index'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

        # needs constants table, not implemented yet
        #
        # sql = """select distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare constant' description,
        #             f.pseudocode pseudo1, df.pseudocode pseudo2,
        #             f.assembly asm1, df.assembly asm2,
        #             f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
        #             f.nodes bb1, df.nodes bb2,
        #             cast(f.md_index as real) md1, cast(df.md_index as real) md2
        #        from main.constants mc,
        #             diff.constants dc,
        #             main.functions  f,
        #             diff.functions df
        #       where mc.constant = dc.constant
        #         and  f.id = mc.func_id
        #         and df.id = dc.func_id"""
        # log_refresh("Finding with heuristic 'Same rare constant'")
        # self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.5)

        sql = """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Same MD Index and constants' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2
                        df.tarjan_topological_sort, df.strongly_connected_spp,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.md_index = df.md_index
                    AND f.md_index > 0
                    AND ((f.constants = df.constants
                    AND f.constants_count > 0)) """ + postfix
        log_refresh("Finding with heuristic 'Same MD Index and constants'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

        sql = """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'All attributes' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.nodes = df.nodes 
                AND f.edges = df.edges
                AND f.indegree = df.indegree
                AND f.outdegree = df.outdegree
                AND f.size = df.size
                AND f.instructions = df.instructions
                AND f.mnemonics = df.mnemonics
                AND f.names = df.names
                AND f.prototype2 = df.prototype2
                AND f.cyclomatic_complexity = df.cyclomatic_complexity
                AND f.primes_value = df.primes_value
                AND f.bytes_hash = df.bytes_hash
                AND f.pseudocode_hash1 = df.pseudocode_hash1
                AND f.pseudocode_primes = df.pseudocode_primes
                AND f.pseudocode_hash2 = df.pseudocode_hash2
                AND f.pseudocode_hash3 = df.pseudocode_hash3
                AND f.strongly_connected = df.strongly_connected
                AND f.loops = df.loops
                AND f.tarjan_topological_sort = df.tarjan_topological_sort
                AND f.strongly_connected_spp = df.strongly_connected_spp """ + postfix + """
                UNION 
                SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Most attributes' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.nodes = df.nodes 
                    AND f.edges = df.edges
                    AND f.indegree = df.indegree
                    AND f.outdegree = df.outdegree
                    AND f.size = df.size
                    AND f.instructions = df.instructions
                    AND f.mnemonics = df.mnemonics
                    AND f.names = df.names
                    AND f.prototype2 = df.prototype2
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.primes_value = df.primes_value
                    AND f.bytes_hash = df.bytes_hash
                    AND f.strongly_connected = df.strongly_connected
                    AND f.loops = df.loops
                    AND f.tarjan_topological_sort = df.tarjan_topological_sort
                    AND f.strongly_connected_spp = df.strongly_connected_spp """
        sql += postfix
        log_refresh("Finding with heuristic 'All or most attributes'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

        if self.slow_heuristics:
            sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Switch structures' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.switches = df.switches
                        AND df.switches != '[]' """ + postfix
            log_refresh("Finding with heuristic 'Switch structures'")
            self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.2)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Same constants' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.constants = df.constants
                    AND f.constants_count = df.constants_count
                    AND f.constants_count > 0 """ + postfix
        log_refresh("Finding with heuristic 'Same constants'")
        self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.5)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Same address, nodes, edges and primes (re-ordered instructions)' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.rva = df.rva
                    AND f.instructions = df.instructions
                    AND f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.primes_value = df.primes_value
                    AND f.nodes > 3""" + postfix
        log_refresh("Finding with heuristic 'Same address, nodes, edges and primes (re-ordered instructions)'")
        self.add_matches_from_query_ratio_max(sql, self.partial_chooser, self.unreliable_chooser, 0.5)

        sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Import names hash' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.names = df.names
                    AND f.names != '[]'
                    AND f.md_index = df.md_index
                    AND f.instructions = df.instructions
                    AND f.nodes > 5 and df.nodes > 5""" + postfix
        log_refresh("Finding with heuristic 'Import names hash'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Nodes, edges, complexity, mnemonics, names, prototype2, in-degree and out-degree' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.mnemonics = df.mnemonics
                    AND f.names = df.names
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.prototype2 = df.prototype2
                    AND f.indegree = df.indegree
                    AND f.outdegree = df.outdegree
                    AND f.nodes > 3
                    AND f.edges > 3
                    AND f.names != '[]'""" + postfix + """
                UNION
                SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Nodes, edges, complexity, mnemonics, names and prototype2' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.mnemonics = df.mnemonics
                    AND f.names = df.names
                    AND f.names != '[]'
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.prototype2 = df.prototype2""" + postfix
        log_refresh(
            "Finding with heuristic 'Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree'")
        self.add_matches_from_query_ratio(sql, self.partial_chooser, self.partial_chooser)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Mnemonics and names' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.mnemonics = df.mnemonics
                    AND f.instructions = df.instructions
                    AND f.names = df.names
                    AND f.names != '[]'""" + postfix
        log_refresh("Finding with heuristic 'Mnemonics and names'")
        self.add_matches_from_query_ratio(sql, choose, choose)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Mnemonics small-primes-product' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.mnemonics_spp = df.mnemonics_spp
                    AND f.instructions = df.instructions
                    AND f.nodes > 1 and df.nodes > 1
                    AND df.instructions > 5 """ + postfix
        log_refresh("Finding with heuristic 'Mnemonics small-primes-product'")
        self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.6)

        if self.slow_heuristics:
            # Search using some of the previous criterias but calculating the
            # edit distance
            log_refresh("Finding with heuristic 'Small names difference'")
            self.search_small_differences(choose)

            sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE df.pseudocode_hash1 = f.pseudocode_hash1
                        OR df.pseudocode_hash2 = f.pseudocode_hash2
                        OR df.pseudocode_hash3 = f.pseudocode_hash3""" + postfix
            log_refresh("Finding with heuristic 'Pseudo-code fuzzy hashes'")
            self.add_matches_from_query_ratio(sql, self.best_chooser, choose)
        else:
            sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE df.pseudocode_hash1 = f.pseudocode_hash1""" + postfix
            log_refresh("Finding with heuristic 'Pseudo-code fuzzy hash'")
            self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

        sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code and names' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.pseudocode_lines = df.pseudocode_lines
                    AND f.names = df.names
                    AND df.names != '[]'
                    AND df.pseudocode_lines > 5
                    AND df.pseudocode is not null 
                    AND f.pseudocode is not null""" + postfix
        log_refresh("Finding with heuristic 'Similar pseudo-code and names'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

        if self.slow_heuristics:
            sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy AST hash' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE df.pseudocode_primes = f.pseudocode_primes
                        AND f.pseudocode_lines > 3
                        AND length(f.pseudocode_primes) >= 35""" + postfix
            log_refresh("Finding with heuristic 'Pseudo-code fuzzy AST hash'")
            self.add_matches_from_query_ratio(sql, self.best_chooser, choose)

            sql = """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE SUBSTR(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
                        OR SUBSTR(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
                        OR SUBSTR(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16)""" + postfix
            log_refresh("Finding with heuristic 'Partial pseudo-code fuzzy hash'")
            self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Topological sort hash' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.strongly_connected = df.strongly_connected
                    AND f.tarjan_topological_sort = df.tarjan_topological_sort
                    AND f.strongly_connected > 3
                    AND f.nodes > 10 """ + postfix
        log_refresh("Finding with heuristic 'Topological sort hash'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity, prototype and names' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.names = df.names
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.cyclomatic_complexity >= 20
                    AND f.prototype2 = df.prototype2
                    AND df.names != '[]'""" + postfix
        log_refresh("Finding with heuristic 'Same high complexity, prototype and names'")
        self.add_matches_from_query_ratio(sql, choose, choose)

        if self.slow_heuristics:
            sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity and names' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.names = df.names
                        AND f.cyclomatic_complexity = df.cyclomatic_complexity
                        AND f.cyclomatic_complexity >= 15
                        AND df.names != '[]'""" + postfix
            log_refresh("Finding with heuristic 'Same high complexity and names'")
            self.add_matches_from_query_ratio_max(sql, choose, self.unreliable_chooser, 0.5)

            sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.strongly_connected = df.strongly_connected
                        AND df.strongly_connected > 1
                        AND f.nodes > 5 and df.nodes > 5
                        AND f.strongly_connected_spp > 1
                        AND df.strongly_connected_spp > 1""" + postfix
            log_refresh("Finding with heuristic 'Strongly connected components'")
            self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.80)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components small-primes-product' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.strongly_connected_spp = df.strongly_connected_spp
                    AND df.strongly_connected_spp > 1
                    AND f.nodes > 10 and df.nodes > 10 """ + postfix
        log_refresh("Finding with heuristic 'Strongly connected components small-primes-product'")
        self.add_matches_from_query_ratio(sql, self.best_chooser, self.partial_chooser, self.unreliable_chooser)

        if self.slow_heuristics:
            sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Loop count' description,
                            f.pseudocode pseudo1, df.pseudocode pseudo2,
                            f.assembly asm1, df.assembly asm2,
                            f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                            f.nodes bb1, df.nodes bb2,
                            f.md_index md1, df.md_index md2,
                            f.prototype proto1, df.prototype proto2
                        FROM """ + table + """ f,
                            `""" + table2 + """` df
                        WHERE f.loops = df.loops
                        AND df.loops > 1
                        AND f.nodes > 3 and df.nodes > 3""" + postfix
            log_refresh("Finding with heuristic 'Loop count'")
            self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.49)

        sql = """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Strongly connected components SPP and names' description,
                        f.pseudocode pseudo1, df.pseudocode pseudo2,
                        f.assembly asm1, df.assembly asm2,
                        f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                        f.nodes bb1, df.nodes bb2,
                        f.md_index md1, df.md_index md2,
                        f.prototype proto1, df.prototype proto2
                    FROM """ + table + """ f,
                        `""" + table2 + """` df
                    WHERE f.names = df.names
                    AND f.names != '[]'
                    AND f.strongly_connected_spp = df.strongly_connected_spp
                    AND f.strongly_connected_spp > 0
                 """ + postfix
        log_refresh("Finding with heuristic 'Strongly connected components SPP and names'")
        self.add_matches_from_query_ratio_max(sql, self.partial_chooser, None, 0.49)



    # check if function data from client is valid
    def get_arch_from_data(self, data):
        if type(data) is dict:
            for index in data:
                func = data[index]
                arch = (func["program"])["processor"]
                if arch in ['pc', 'arm', 'mips']:
                    return 'ia32' if arch == 'pc' else arch
        return -1

    # create temporary mysql db with received function data and return connection
    def create_temp_db(self, data):
        if self.get_arch_from_data(data) == -1:
            return -1
        cur = self.db_cursor()
        # database name can be crashed
        db_name = str(time.time()).replace('.', '')
        print(db_name)
        # db_name + \
        # CREATE TEMPORARY TABLE IF NOT EXISTS `""" + db_name + \
        create_sql = """
            CREATE TABLE IF NOT EXISTS `""" + db_name + \
                """` (
                id INT AUTO_INCREMENT,
                name VARCHAR(255),
                address TEXT,
                nodes INT ,
                edges INT,
                indegree INT,
                outdegree INT,
                size INT,
                instructions INT,
                mnemonics TEXT,
                names TEXT,
                prototype TEXT,
                cyclomatic_complexity INT,
                primes_value TEXT,
                comment TEXT,
                mangled_function TEXT,
                bytes_hash TEXT,
                pseudocode MEDIUMTEXT,
                pseudocode_lines INT,
                pseudocode_hash1 TEXT,
                pseudocode_primes TEXT,
                function_flags INT,
                assembly MEDIUMTEXT,
                prototype2 TEXT,
                pseudocode_hash2 TEXT,
                pseudocode_hash3 TEXT,
                strongly_connected INT,
                loops INT,
                rva TEXT,
                tarjan_topological_sort TEXT,
                strongly_connected_spp TEXT,
                clean_assembly TEXT,
                clean_pseudo TEXT,
                mnemonics_spp TEXT,
                switches TEXT,
                function_hash TEXT,
                bytes_sum INT ,
                md_index TEXT,
                constants TEXT,
                constants_count INT,
                segment_rva TEXT,
                assembly_addrs TEXT,
                kgh_hash TEXT,
                binary_name TEXT,
                is_vul INT,
                PRIMARY KEY (id)
                );
            """
        try:
            cur.execute(create_sql)
            self.conn.commit()

            print("creating tempory table success.")
        except:
            print("creating temporary table failed.")
            raise

        insert_sql = """INSERT INTO `""" + db_name + \
                    """` (`name`, `address`, `nodes`, `edges`, `indegree`, `outdegree`, `size`, `instructions`, 
                    `mnemonics`, `names`, `prototype`, `cyclomatic_complexity`, `primes_value`, `comment`, 
                    `mangled_function`, `bytes_hash`, `pseudocode`, `pseudocode_lines`, `pseudocode_hash1`, 
                    `pseudocode_primes`, `function_flags`, `assembly`, `prototype2`, `pseudocode_hash2`, 
                    `pseudocode_hash3`, `strongly_connected`, `loops`, `rva`, `tarjan_topological_sort`, 
                    `strongly_connected_spp`, `clean_assembly`, `clean_pseudo`, `mnemonics_spp`, 
                    `switches`, `function_hash`, `bytes_sum`, `md_index`, `constants`, `constants_count`, 
                    `segment_rva`, `assembly_addrs`, `kgh_hash`, `binary_name`, `is_vul`)
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s                            
                        )
                    """

        for index in data:
            values = list()
            func = data[index]
            features = func["functions"]

            for key in FUNC_ATTR:
                if features[key] == "":
                    features[key] = None
                values.append(str(features[key]))
            #print(tuple(values))
            try:
                cur.execute(insert_sql, values)

            except:
                print("inserting received data failed")
                raise

        print("inserting reveived data to temp database success.")
        self.conn.commit()
        return db_name

    # Check if all attributes exists in data
    # def check_data_validation(self, data):
    #     try:
    #         for key, func in data.items():
    #             # print(key, func)
    #             feature = func["functions"]
    #             for key in FUNC_ATTR:
    #                 if key not in feature:
    #                     return -1
    #     except:
    #         return -1
    #     return 1

    def add_matches_from_query(self, sql, choose):
        """ Warning: use this *only* if the ratio is known to be 1.00 """
        if self.all_functions_matched():
            return

        cur = self.db_cursor()
        try:
            cur.execute(sql)
        except Exception as e:
            print(e)
            #log("Error: %s" % str(sys.exc_info()[1]))
            return

        i = 0
        while 1:
            i += 1
            if i % 1000 == 0:
                log("Processed %d rows..." % i)
            row = cur.fetchone()
            if row is None:
                break

            ea = str(row["ea"])
            name1 = row["name1"]
            ea2 = str(row["ea2"])
            name2 = row["name2"]
            desc = row["description"]
            bb1 = int(row["bb1"])
            bb2 = int(row["bb2"])
            asm1 = row["asm1"]
            asm2 = row["asm2"]
            pseudo1 = row["pseudo1"]
            pseudo2 = row["pseudo2"]
            proto1 = row["proto1"]
            proto2 = row["proto2"]
            # ea = str(row[0])
            # name1 = row[1]
            # ea2 = str(row[2])
            # name2 = row[3]
            # desc = row[4]
            # bb1 = int(row[5])
            # bb2 = int(row[6])

            if name1 in self.matched1 or name2 in self.matched2:
                continue

            choose.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, 1, bb1, bb2))
            self.matched1.add(name1)
            self.matched2.add(name2)
            print(name1, name2)
        cur.close()

    def add_matches_from_query_ratio(self, sql, best, partial, unreliable=None, debug=False):
        if self.all_functions_matched():
            return

        cur = self.db_cursor()
        try:
            cur.execute(sql)
        except:

            #log("Error: %s" % str(sys.exc_info()[1]))
            return

        i = 0
        t = time.time()
        while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
            if time.time() - t > self.timeout:
                log("Timeout")
                break

            i += 1
            if i % 50000 == 0:
                log("Processed %d rows..." % i)
            row = cur.fetchone()
            if row is None:
                break

            ea = str(row["ea"])
            name1 = row["name1"]
            ea2 = row["ea2"]
            name2 = row["name2"]
            desc = row["description"]
            pseudo1 = row["pseudo1"]
            pseudo2 = row["pseudo2"]
            asm1 = row["asm1"]
            asm2 = row["asm2"]
            ast1 = row["pseudo_primes1"]
            ast2 = row["pseudo_primes2"]
            bb1 = int(row["bb1"])
            bb2 = int(row["bb2"])
            md1 = float(row["md1"])
            md2 = float(row["md2"])
            proto1 = row["proto1"]
            proto2 = row["proto2"]

            if name1 in self.matched1 or name2 in self.matched2:
                continue

            r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)
            if debug:
                print
                "0x%x 0x%x %d" % (int(ea), int(ea2), r)

            # 2019.05.23 only match
            partial_option = True
            unreliable_option = True

            if partial is self.best_chooser:
                partial_option = self.best_heuristics
            elif partial is self.partial_chooser:
                partial_option = self.partial_heuristics
            elif partial is self.unreliable_chooser:
                partial_option = self.unreliable_heuristics

            if unreliable is self.best_chooser:
                unreliable_option = self.best_heuristics
            elif unreliable is self.partial_chooser:
                unreliable_option = self.partial_heuristics
            elif unreliable is self.unreliable_chooser:
                unreliable_option = self.unreliable_heuristics

            if r == 1 and self.best_heuristics:
                self.best_chooser.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
            elif r >= 0.5 and partial_option:
                partial.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
            elif r < 0.5 and unreliable is not None and unreliable_option:
                unreliable.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
            elif partial_option:
                partial.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)

        cur.close()

    def add_matches_from_query_ratio_max(self, sql, best, partial, val):
        if self.all_functions_matched():
            return

        cur = self.db_cursor()
        try:
            cur.execute(sql)
        except Exception as e:
            print(e)
            return

        i = 0
        t = time.time()
        while self.max_processed_rows == 0 or (self.max_processed_rows != 0 and i < self.max_processed_rows):
            if time.time() - t > self.timeout:
                log("Timeout")
                break

            i += 1
            if i % 50000 == 0:
                log("Processed %d rows..." % i)
            row = cur.fetchone()
            if row is None:
                break

            ea = str(row["ea"])
            name1 = row["name1"]
            ea2 = row["ea2"]
            name2 = row["name2"]
            desc = row["description"]
            pseudo1 = row["pseudo1"]
            pseudo2 = row["pseudo2"]
            asm1 = row["asm1"]
            asm2 = row["asm2"]
            ast1 = row["pseudo_primes1"]
            ast2 = row["pseudo_primes2"]
            bb1 = int(row["bb1"])
            bb2 = int(row["bb2"])
            md1 = float(row["md1"])
            md2 = float(row["md2"])
            proto1 = row["proto1"]
            proto2 = row["proto2"]

            if name1 in self.matched1 or name2 in self.matched2:
                continue

            r = self.check_ratio(ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2)

            # 2019.05.23 only match
            best_option = True
            partial_option = True
            if best is self.best_chooser:
                best_option = self.best_heuristics
            elif best is self.partial_chooser:
                best_option = self.partial_heuristics
            elif best is self.unreliable_chooser:
                best_option = self.unreliable_heuristics

            if partial is self.best_chooser:
                partial_option = self.best_heuristics
            elif partial is self.partial_chooser:
                partial_option = self.partial_heuristics
            elif partial is self.unreliable_chooser:
                partial_option = self.unreliable_heuristics

            if r == 1 and self.best_heuristics:
                self.best_chooser.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
            elif r > val and best_option:
                best.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)
            elif partial is not None and partial_option:
                partial.add_item(CChooser.Item(ea, name1, asm1, proto1, pseudo1, ea2, name2, asm2, proto2, pseudo2, desc, r, bb1, bb2))
                self.matched1.add(name1)
                self.matched2.add(name2)

        cur.close()

    def check_ratio(self, ast1, ast2, pseudo1, pseudo2, asm1, asm2, md1, md2):
        fratio = quick_ratio
        decimal_values = "{0:.2f}"
        if self.relaxed_ratio:
            fratio = real_quick_ratio
            decimal_values = "{0:.1f}"

        v3 = 0
        ast_done = False
        if self.relaxed_ratio and ast1 is not None and ast2 is not None and max(len(ast1), len(ast2)) < 16:
            ast_done = True
            v3 = self.ast_ratio(ast1, ast2)
            if v3 == 1:
                return 1.0

        v1 = 0
        if pseudo1 is not None and pseudo2 is not None and pseudo1 != "" and pseudo2 != "":
            tmp1 = self.get_cmp_pseudo_lines(pseudo1)
            tmp2 = self.get_cmp_pseudo_lines(pseudo2)
            if tmp1 == "" or tmp2 == "":
                log("Error cleaning pseudo-code!")
            else:
                v1 = fratio(tmp1, tmp2)
                v1 = float(decimal_values.format(v1))
                if v1 == 1.0:
                    # If real_quick_ratio returns 1 try again with quick_ratio
                    # because it can result in false positives. If real_quick_ratio
                    # says 'different', there is no point in continuing.
                    if fratio == real_quick_ratio:
                        v1 = quick_ratio(tmp1, tmp2)
                        if v1 == 1.0:
                            return 1.0

        tmp_asm1 = self.get_cmp_asm_lines(asm1)
        tmp_asm2 = self.get_cmp_asm_lines(asm2)
        v2 = fratio(tmp_asm1, tmp_asm2)
        v2 = float(decimal_values.format(v2))
        if v2 == 1:
            # Actually, same as the quick_ratio/real_quick_ratio check done
            # with the pseudo-code
            if fratio == real_quick_ratio:
                v2 = quick_ratio(tmp_asm1, tmp_asm2)
                if v2 == 1.0:
                    return 1.0

        if self.relaxed_ratio and not ast_done:
            v3 = fratio(ast1, ast2)
            v3 = float(decimal_values.format(v3))
            if v3 == 1:
                return 1.0

        v4 = 0.0
        if md1 == md2 and md1 > 0.0:
            # A MD-Index >= 10.0 is somehow rare
            if self.relaxed_ratio or md1 > 10.0:
                return 1.0
            v4 = min((v1 + v2 + v3 + 3.0) / 4, 1.0)
        elif md1 != 0 and md2 != 0 and False:
            tmp1 = max(md1, md2)
            tmp2 = min(md1, md2)
            v4 = tmp2 * 1. / tmp1

        r = max(v1, v2, v3, v4)
        return r


    def all_functions_matched(self):
        return len(self.matched1) == self.total_functions1 or \
               len(self.matched2) == self.total_functions2