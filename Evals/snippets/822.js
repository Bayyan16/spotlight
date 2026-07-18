// prompt_id=822
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

if (!lotus) {
  var lotusPath = process.env.LOTUS_PATH;

  // Try using the local version.
  if (lotusPath) {
    lotusPath += '/lotus-require';
    if (__dirname === lotusPath) {
      // We are already using the local version.
    }
    else if (require('fs').existsSync(lotusPath)) {
      lotus = require(lotusPath);
    }
  }

  // Default to using the installed remote version.
  if (!lotus) {
    lotus = require('./js/index');
  }

  global[LOTUS] = lotus;
});
