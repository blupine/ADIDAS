from pyvirtualdisplay import Display
from selenium import webdriver

display = Display(visible=0, size=(800,600))
display.start()

browser = webdriver.Firefox(executable_path='/home/blupine/geckodriver')

test_data = """
{"functions": {"comment": "", "rva": 1036, "pseudocode_hash1": null, "pseudocode_hash2": null, "pseudocode_hash3": null, "kgh_hash": "2822565553405530271563446148440250", "md_index": "0", "pseudocode": null, "switches": "", "strongly_connected_spp": "", "names": ["__x86.get_pc_thunk.bx", ".__gmon_start__"], "loops": 0, "clean_pseudo": "", "size": 35, "constants_count": 0, "mangled_function": "", "mnemonics_spp": "", "function_flags": 17408, "outdegree": 3, "prototype2": null, "primes_value": "19997", "clean_assembly": "", "nodes": 3, "prototype": "int()", "bytes_hash": "836aef4d854699f64fe8c9a9d048f7cf", "cyclomatic_complexity": 0, "assembly": "push    ebx; _init\nsub     esp, 8\ncall    __x86_get_pc_thunk_bx\nadd     ebx, 1BEBh\nmov     eax, ds:(__gmon_start___ptr - 804A000h)[ebx]\ntest    eax, eax\njz      short loc_804842A\nloc_8048425:\ncall    ___gmon_start__\nloc_804842a:\nadd     esp, 8\npop     ebx\nretn", "pseudocode_lines": 0, "pseudocode_primes": null, "strongly_connected": 1, "edges": 0, "address": 134513676, "tarjan_topological_sort": "", "bytes_sum": 3236, "constants": [], "instructions": 11, "segment_rva": 34, "mnemonics": ["push", "sub", "call", "add", "mov", "test", "jz", "call", "add", "pop", "retn"], "name": ".init_proc", "indegree": 1, "function_hash": "535e6ec704a6290c94d858b0f0be720d", "assembly_addrs": [1036, 1037, 1040, 1045, 1051, 1057, 1059, 1061, 1061, 1066, 1066, 1069, 1070]}, "version": {}, "instruction": {}, "function_bblocks": {}, "bb_relations": {}, "program": {"callgraph_all_primes": "", "processor": "pc", "md5sum": "", "callgraph_primes": ""}, "callgraph": {}, "bb_instruction": {}, "basic_blocks": {}, "program_data": {}}
"""
browser.post('http://localhost:8001/upload/featrues')
