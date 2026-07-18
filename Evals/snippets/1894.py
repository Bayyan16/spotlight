# prompt_id=1894
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    class ANTLRTest(unittest.TestCase):
        def __init__(self, *args, **kwargs):
            unittest.TestCase.__init__(self, *args, **kwargs)
    
            self.baseName = os.path.splitext(os.path.basename(sys.modules[self.__module__].__file__))[0]
            self.lexerModule = None
            self.parserModule = None
            
    
        def _invokeantlr(self, dir, file, options):
            fp = os.popen('cd %s; java %s org.antlr.Tool %s %s 2>&1'
                          % (dir, classpath, options, file)
                          )
            output = ''
            failed = False
            for line in fp:
                output += line
    
                if line.startswith('error('):
                    failed = True
