# prompt_id=1895
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    # loop through every hg changeset
    for cset in range(int(tip) + 1):
    
        # incremental, already seen
        if hgvers.has_key(str(cset)):
            continue
        hgnewcsets += 1
    
        # get info
        log_data = os.popen('hg log -r %d --template "{tags}\n{date|date}\n{author}\n"' % cset).readlines()
        tag = log_data[0].strip()
        date = log_data[1].strip()
        user = log_data[2].strip()
        parent = hgparents[str(cset)][0]
        mparent = hgparents[str(cset)][1]
    
        #get comment
        (fdcomment, filecomment) = tempfile.mkstemp()
        csetcomment = os.popen('hg log -r %d --template "{desc}"' % cset).read().strip()
