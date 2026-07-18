# prompt_id=1706
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    alignments = sequence_files
    
    # read in dgen stat from file
    
    # (have to wait for file to exist sometimes)
    while not os.path.exists(stat_file):
        time.sleep(1)
    
    with(open(stat_file, "r")) as s:
        lines = s.readlines()
        taxa = eval(lines[0].split(None, 1)[1])
        stat_species_tree = lines[1].split(None, 2)[2].replace("\n", "")
        stat_species_network = lines[2].split(None, 2)[2].replace("\n", "")
        outgroup = lines[3].split(None, 1)[1].replace("\n", "")
    
        invariants = []
        for oneInvLine in range(4,len(lines)):
            this_line_invariant_group = eval(lines[oneInvLine].split(None, 6)[6])
            invariants.append(this_line_invariant_group)
