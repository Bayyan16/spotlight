# prompt_id=1724
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    f_locals.update(vars)
    return eval(code, self.f_globals, f_locals)

def exec_(self, code, **vars):
    """ exec 'code' in the frame

        'vars' are optiona; additional local variables
    """
    f_locals = self.f_locals.copy()
    f_locals.update(vars)
    exec(code, self.f_globals, f_locals)

def repr(self, object):
    """ return a 'safe' (non-recursive, one-line) string repr for 'object'
    """
    return saferepr(object)

def is_true(self, object):
    return object
