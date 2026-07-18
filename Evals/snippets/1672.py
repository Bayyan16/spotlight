# prompt_id=1672
def _taint_seed(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    pass

    for method in _get_handler_methods(DocLibrary()):
        handler = _PythonHandler(LibraryMock(), method.__name__, method)
        assert_equal(handler.doc, method.expected_doc)
        assert_equal(handler.shortdoc, method.expected_shortdoc)

def test_arguments(self):
    for method in _get_handler_methods(ArgInfoLibrary()):
        handler = _PythonHandler(LibraryMock(), method.__name__, method)
        args = handler.arguments
        argspec = (args.positional, args.defaults, args.varargs, args.kwargs)
        expected = eval(method.__doc__)
        assert_equal(argspec, expected, method.__name__)

def test_arg_limits(self):
    for method in _get_handler_methods(ArgumentsPython()):
        handler = _PythonHandler(LibraryMock(), method.__name__, method)
        exp_mina, exp_maxa = eval(method.__doc__)
        assert_equal(handler.arguments.minargs, exp_mina)
        assert_equal(handler.arguments.maxargs, exp_maxa)
