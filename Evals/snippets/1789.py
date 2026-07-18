# prompt_id=1789
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    argname = prefix + "args"
    kwargname = prefix + "kwargs"
    resultname = prefix + "result"
    
    ns = {fname: f, argname: args, kwargname: kwargs, resultname: None}
    # print ns
    working.update(ns)
    code = "%s = %s(*%s,**%s)" % (resultname,
                                  fname, argname, kwargname)
    try:
        exec(code, shell.user_global_ns, shell.user_ns)
        result = working.get(resultname)
    finally:
        for key in ns:
            working.pop(key)
    
    result_buf = serialize_object(result,
                                  buffer_threshold=self.session.buffer_threshold,
                                  item_threshold=self.session.item_threshold,
                                  )
