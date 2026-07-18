# prompt_id=1777
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    safe_name = SAFE_MODULE_NAME.sub("_", target, len(target))
    module_name = "bento_hook_%s" % safe_name
    main_file = os.path.abspath(target)
    module = imp.new_module(module_name)
    module.__file__ = main_file
    code = open(main_file).read()
    
    sys.path.insert(0, os.path.dirname(main_file))
    try:
        exec(compile(code, main_file, 'exec'), module.__dict__)
        sys.modules[module_name] = module
    finally:
        sys.path.pop(0)
    
    module.root_path = main_file
    if not "startup" in __INIT_FUNCS:
        module.startup = dummy_startup
    if not "options" in __INIT_FUNCS:
        module.options = dummy_options
