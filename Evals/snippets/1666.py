# prompt_id=1666
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    snippet_execstr = utool.execstr_dict(snippet_locals, 'snippet_locals')
    exec(snippet_execstr)

#
#
# Development code
RUN_DEV = True  # RUN_DEV = '__IPYTHON__' in vars()
if RUN_DEV:
    dev_locals = run_dev(main_locals['ibs'])
    dev_execstr = utool.execstr_dict(dev_locals, 'dev_locals')
    exec(dev_execstr)

command = ut.get_argval('--eval', type_=str, default=None)
if command is not None:
    result = eval(command, globals(), locals())
    print('result = %r' % (result,))
    #ibs.search_annot_notes('360')

#
#
