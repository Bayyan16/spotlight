// prompt_id=890
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

      cpu1_shizzle += 'var SR_CU1 = ' + n64js.toString32(SR_CU1) + ';\n';
      cpu1_shizzle += 'var FPCSR_C = ' + n64js.toString32(FPCSR_C) + ';\n';
      fragment.body_code = cpu1_shizzle + '\n\n' + fragment.body_code;
    }

    var code = 'return function fragment_' + n64js.toString32(fragment.entryPC) + '_' + fragment.opsCompiled + '(c, rlo, rhi, ram) {\n' + fragment.body_code + '}\n';

    // Clear these strings to reduce garbage
    fragment.body_code ='';

    fragment.func = new Function(code)();
    fragment.nextFragments = [];
    for (var i = 0; i < fragment.opsCompiled; i++) {
      fragment.nextFragments.push(undefined);
    }
    fragment = lookupFragment(c.pc);
  }

  return fragment;
}
});
