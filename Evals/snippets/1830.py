# prompt_id=1830
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    if __name__ == "__main__":
        if sys.version_info >= (3, 0):
            exec("def do_exec(co, loc): exec(co, loc)\n")
            import pickle
            sources = sources.encode("ascii") # ensure bytes
            sources = pickle.loads(zlib.decompress(base64.decodebytes(sources)))
        else:
            import cPickle as pickle
            exec("def do_exec(co, loc): exec co in loc\n")
            sources = pickle.loads(zlib.decompress(base64.decodestring(sources)))
    
        importer = DictImporter(sources)
        sys.meta_path.insert(0, importer)
    
        entry = "import pytest; raise SystemExit(pytest.cmdline.main())"
        do_exec(entry, locals()) # noqa
