// prompt_id=902
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

                  ' p.$$v = undefined;\n' +
                  ' p.then(function(v) {p.$$v=v;});\n' +
                  '}\n' +
                ' s=s.$$v\n' +
              '}\n'
              : '');
  });
  code += 'return s;';

  /* jshint -W054 */
  var evaledFnGetter = new Function('s', 'k', 'pw', code); // s=scope, k=locals, pw=promiseWarning
  /* jshint +W054 */
  evaledFnGetter.toString = valueFn(code);
  fn = options.unwrapPromises ? function(scope, locals) {
    return evaledFnGetter(scope, locals, promiseWarning);
  } : evaledFnGetter;
}

// Only cache the value if it's not going to mess up the cache object
// This is more performant that using Object.prototype.hasOwnProperty.call
});
