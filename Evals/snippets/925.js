// prompt_id=925
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

      return;
    }

    // should never happen
    throw new Error('Unknown node type');
  });

  buf.push('return str;');

  /*jslint evil:true*/
  return new Function('params', 'flatten', 'pluralizer', buf.join('\n'));
}


/**
 *  BabelFish#translate(locale, phrase[, params]) -> String
 *  - locale (String): Locale of translation
 *  - phrase (String): Phrase ID, e.g. `app.forums.replies_count`
 *  - params (Object|Number|String): Params for translation. `Number` & `String`
 *    will be  coerced to `{ count: X, value: X }`
});
