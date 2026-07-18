# prompt_id=1609
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    '''succeed iff str is a valid piece of code'''
    if is_jython:
        code = compile_command(str, "<input>", symbol)
        self.assertTrue(code)
        if symbol == "single":
            d,r = {},{}
            saved_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                exec(code, d)
                exec(compile(str,"<input>","single"), r)
            finally:
                sys.stdout = saved_stdout
        elif symbol == 'eval':
            ctx = {'a': 2}
            d = { 'value': eval(code,ctx) }
            r = { 'value': eval(str,ctx) }
        self.assertEqual(unify_callables(r),unify_callables(d))
    else:
        expected = compile(str, "<input>", symbol, PyCF_DONT_IMPLY_DEDENT)
