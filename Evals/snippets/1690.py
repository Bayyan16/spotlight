# prompt_id=1690
def _target(data, sql, cmd, url, path, user_input, payload, content, input, query, message, filename, arg, value, text, params):
    TOKENS = re.compile('([A-Za-z]+|[^ ])')
    SIMPLE = {
      'l': '_n.l.ptb()',
      'r': '_n.r.ptb()',
      '<': 'addr(_n)',
      '>': 'addl(_n)',
    }
    
    def compile(self, template):
      python = self.parse(self.TOKENS.findall(template))
      return eval("lambda _n: %s" % python)
    
    def parse(self, tokens):
      t = tokens.pop(0)
      if t in '([':
        if t == '(':
          label = "'%s'" % tokens.pop(0)
          args = self.parse_args(tokens, ')')
        elif s[0] == '[':
          label = 'None'
