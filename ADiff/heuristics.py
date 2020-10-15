HEUR_TYPE_NONE = 0
HEUR_TYPE_RATIO = 1
HEUR_TYPE_RATIO_MAX = 2

HEUR_FLAG_NONE        = 0
HEUR_FLAG_UNRELIABLE  = 1
HEUR_FLAG_SLOW        = 2

HEURISTICS = []

# Best -----------------------------------------------


HEURISTICS.append({
    "name":"Same RVA and hash",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same RVA and hash' description,
                    f.nodes bb1, df.nodes bb2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE (df.rva = f.rva
                    OR df.segment_rva = f.segment_rva)
                    AND df.bytes_hash = f.bytes_hash
                    AND df.instructions = f.instructions
                    AND ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                    OR (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Same hash",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same order and hash' description,
                    f.nodes bb1, df.nodes bb2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE df.bytes_hash = f.bytes_hash
                    AND df.instructions = f.instructions
                    AND ((f.name = df.name and substr(f.name, 1, 4) != 'sub_')
                    OR (substr(f.name, 1, 4) = 'sub_' or substr(df.name, 1, 4)))
                    AND ((f.nodes > 1 and df.nodes > 1
                    AND f.instructions > 5 and df.instructions > 5)
                    OR f.instructions > 10 and df.instructions > 10)""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Function hash",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Function hash' description,
                    f.nodes bb1, df.nodes bb2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.function_hash = df.function_hash 
                    AND ((f.nodes > 1 and df.nodes > 1
                    AND f.instructions > 5 and df.instructions > 5)
                    OR f.instructions > 10 and df.instructions > 10)""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Bytes hash and names",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Bytes hash and names' description,
                    f.nodes bb1, df.nodes bb2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.bytes_hash = df.bytes_hash
                    AND f.names = df.names
                    AND f.names != '[]'
                    AND f.instructions > 5 and df.instructions > 5""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Bytes hash",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Bytes hash' description,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.bytes_hash = df.bytes_hash
                    AND f.instructions > 5 and df.instructions > 5""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Bytes sum",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Bytes sum' description,
                    f.nodes bb1, df.nodes bb2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.bytes_sum = df.bytes_sum
                    AND f.size = df.size
                    AND f.mnemonics = df.mnemonics
                    AND f.instructions > 5 and df.instructions > 5""",
    "flags":HEUR_FLAG_UNRELIABLE
})

HEURISTICS.append({
    "name":"Equal assembly or pseudo-code",
    "category":"Best",
    "ratio":HEUR_TYPE_NONE,
    "sql" : """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal pseudo-code' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.pseudocode = df.pseudocode
                    AND df.pseudocode is not null
                    AND f.pseudocode_lines >= 5 %POSTFIX% 
                    AND f.name not like 'nullsub%'
                    AND df.name not like 'nullsub%'
                UNION
                SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Equal assembly' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.assembly = df.assembly
                    AND df.assembly is not null
                    AND f.instructions >= 4 and df.instructions >= 4
                    AND f.name not like 'nullsub%'
                    AND df.name not like 'nullsub%' """,
    "flags":HEUR_FLAG_NONE
})


# Best + ratio-----------------------------------------------
HEURISTICS.append({
    "name":"Same cleaned up assembly or pseudo-code",
    "category":"Best",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same cleaned up assembly or pseudo-code' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE (f.clean_assembly = df.clean_assembly
                    OR f.clean_pseudo = df.clean_pseudo) 
                    AND f.pseudocode_lines > 5 and df.pseudocode_lines > 5
                    AND f.name not like 'nullsub%'
                    AND df.name not like 'nullsub%' """,
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Same address, nodes, edges and mnemonics",
    "category":"Best",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same address, nodes, edges and mnemonics' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.rva = df.rva
                    AND f.instructions = df.instructions
                    AND f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.mnemonics = df.mnemonics %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

# Partial

HEURISTICS.append({
    "name":"Same rare KOKA hash",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare KOKA hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
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
                    AND f.nodes > 3 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Same rare MD Index",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same rare MD Index' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
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
                AND f.nodes > 10 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})


HEURISTICS.append({
    "name":"Same MD Index and constants",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """ SELECT DISTINCT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same MD Index and constants' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2
                    df.tarjan_topological_sort, df.strongly_connected_spp,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.md_index = df.md_index
                    AND f.md_index > 0
                    AND ((f.constants = df.constants
                    AND f.constants_count > 0)) %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})



HEURISTICS.append({
    "name":"All or most attributes",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """ SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'All attributes' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
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
                    AND f.strongly_connected_spp = df.strongly_connected_spp %POSTFIX% 
                UNION 
                SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Most attributes' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
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
                    AND f.strongly_connected_spp = df.strongly_connected_spp %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})


# Partial + slow


HEURISTICS.append({
    "name":"Switch structures",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Switch structures' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.switches = df.switches
                    AND df.switches != '[]'
                    AND f.nodes > 5 AND df.nodes > 5
                    %POSTFIX%""",
    "flags":HEUR_FLAG_SLOW,
})

HEURISTICS.append({
    "name":"Same constants",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same constants' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.constants = df.constants
                    AND f.constants_count = df.constants_count
                    AND f.constants_count > 0 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE,
    "min" : 0.5
})


HEURISTICS.append({
    "name":"Same address, nodes, edges and primes (re-ordered instructions)",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Same address, nodes, edges and primes (re-ordered instructions)' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.rva = df.rva
                    AND f.instructions = df.instructions
                    AND f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.primes_value = df.primes_value
                    AND f.nodes > 3 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE,
    "min" : 0.5
})


HEURISTICS.append({
    "name":"Import names hash",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Import names hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.names = df.names
                    AND f.names != '[]'
                    AND f.md_index = df.md_index
                    AND f.instructions = df.instructions
                    AND f.nodes > 5 and df.nodes > 5 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Nodes, edges, complexity, mnemonics, names, prototype, in-degree and out-degree",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Nodes, edges, complexity, mnemonics, names, prototype2, in-degree and out-degree' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
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
                    AND f.names != '[]' %POSTFIX% 
                UNION
                SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Nodes, edges, complexity, mnemonics, names and prototype2' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.nodes = df.nodes
                    AND f.edges = df.edges
                    AND f.mnemonics = df.mnemonics
                    AND f.names = df.names
                    AND f.names != '[]'
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.prototype2 = df.prototype2 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Mnemonics and names",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Mnemonics and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.mnemonics = df.mnemonics
                    AND f.instructions = df.instructions
                    AND f.names = df.names
                    AND f.names != '[]' %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Mnemonics small-primes-product",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Mnemonics small-primes-product' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.mnemonics_spp = df.mnemonics_spp
                    AND f.instructions = df.instructions
                    AND f.nodes > 1 and df.nodes > 1
                    AND df.instructions > 5 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE,
    "min" : 0.6
})

# Partial + slow

HEURISTICS.append({
    "name":"Pseudo-code fuzzy hashes",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE df.pseudocode_hash1 = f.pseudocode_hash1
                    OR df.pseudocode_hash2 = f.pseudocode_hash2
                    OR df.pseudocode_hash3 = f.pseudocode_hash3 %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Similar pseudo-code and names",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Similar pseudo-code and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.pseudocode_lines = df.pseudocode_lines
                    AND f.names = df.names
                    AND df.names != '[]'
                    AND df.pseudocode_lines > 5
                    AND df.pseudocode is not null 
                    AND f.pseudocode is not null %POSTFIX%""",
    "flags":HEUR_FLAG_NONE
})

HEURISTICS.append({
    "name":"Pseudo-code fuzzy AST hash",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Pseudo-code fuzzy AST hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE df.pseudocode_primes = f.pseudocode_primes
                    AND f.pseudocode_lines > 3
                    AND length(f.pseudocode_primes) >= 35 %POSTFIX%""",
    "flags":HEUR_FLAG_SLOW
})

HEURISTICS.append({
    "name":"Partial pseudo-code fuzzy hash",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT distinct f.address ea, f.name name1, df.address ea2, df.name name2, 'Partial pseudo-code fuzzy hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE SUBSTR(df.pseudocode_hash1, 1, 16) = substr(f.pseudocode_hash1, 1, 16)
                    OR SUBSTR(df.pseudocode_hash2, 1, 16) = substr(f.pseudocode_hash2, 1, 16)
                    OR SUBSTR(df.pseudocode_hash3, 1, 16) = substr(f.pseudocode_hash3, 1, 16) %POSTFIX%""",
    "flags":HEUR_FLAG_SLOW,
    "min" : 0.5
})


HEURISTICS.append({
    "name":"Topological sort hash",
    "category":"Unreliable",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Topological sort hash' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.strongly_connected = df.strongly_connected
                    AND f.tarjan_topological_sort = df.tarjan_topological_sort
                    AND f.strongly_connected > 3
                    AND f.nodes > 10 %POSTFIX%""",
    "flags": HEUR_FLAG_NONE
})


HEURISTICS.append({
    "name":"Same high complexity, prototype and names",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity, prototype and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.names = df.names
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.cyclomatic_complexity >= 20
                    AND f.prototype2 = df.prototype2
                    AND df.names != '[]' + %POSTFIX%""",
    "flags": HEUR_FLAG_NONE
})


HEURISTICS.append({
    "name":"Same high complexity and names",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Same high complexity and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.names = df.names
                    AND f.cyclomatic_complexity = df.cyclomatic_complexity
                    AND f.cyclomatic_complexity >= 15
                    AND df.names != '[]' %POSTFIX%""",
    "flags": HEUR_FLAG_SLOW,
    "min" : 0.5
})

HEURISTICS.append({
    "name":"Strongly connected components",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.strongly_connected = df.strongly_connected
                    AND df.strongly_connected > 1
                    AND f.nodes > 5 and df.nodes > 5
                    AND f.strongly_connected_spp > 1
                    AND df.strongly_connected_spp > 1 %POSTFIX%""",
    "flags": HEUR_FLAG_SLOW,
    "min" : 0.8
})


HEURISTICS.append({
    "name":"Strongly connected components small-primes-product",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Strongly connected components small-primes-product' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.strongly_connected_spp = df.strongly_connected_spp
                    AND df.strongly_connected_spp > 1
                    AND f.nodes > 10 and df.nodes > 10 %POSTFIX%""",
    "flags": HEUR_FLAG_SLOW
})


HEURISTICS.append({
    "name":"Loop count",
    "category":"Unreliable",
    "ratio":HEUR_TYPE_RATIO,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2, 'Loop count' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.loops = df.loops
                    AND df.loops > 1
                    AND f.nodes > 3 and df.nodes > 3 %POSTFIX%""",
    "flags": HEUR_FLAG_SLOW,
})

HEURISTICS.append({
    "name":"Strongly connected components SPP and names",
    "category":"Partial",
    "ratio":HEUR_TYPE_RATIO_MAX,
    "sql" : """SELECT f.address ea, f.name name1, df.address ea2, df.name name2,
                    'Strongly connected components SPP and names' description,
                    f.pseudocode pseudo1, df.pseudocode pseudo2,
                    f.assembly asm1, df.assembly asm2,
                    f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,
                    f.nodes bb1, df.nodes bb2,
                    f.md_index md1, df.md_index md2,
                    f.prototype proto1, df.prototype proto2,
                    f.is_vul is_vul, f.comment comment
                FROM %TABLE1% f, `%TABLE2%` df
                WHERE f.names = df.names
                    AND f.names != '[]'
                    AND f.strongly_connected_spp = df.strongly_connected_spp
                    AND f.strongly_connected_spp > 0 %POSTFIX%""",
    "flags": HEUR_FLAG_SLOW,
    "min" : 0.49
})


def get_all_heuristics():
    return HEURISTICS

def get_duptest_heuristics():
    dup_test = ["Function hash", "Equal assembly or pseudo-code", "Same cleaned up assembly or pseudo-code"]
    ret = []
    for h in HEURISTICS:
        if h["name"] in dup_test:
            ret.append(h)

    return ret

def get_selected_heuristics(Type):
    if Type not in ["Best", "Partial", "Unreliable"]:
        print("Err : get_selected_heuristics")
        return

    ret = []
    for h in HEURISTICS:
        if h["category"] == Type:
            ret.append(h)

    return ret































