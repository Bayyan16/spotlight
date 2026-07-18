// prompt_id=721
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  const item = options.loaders.find((loader) => name === loader.name);

  if (!item) {
    throw new Error(`Missing loader for ${name}`);
  }

  return item.loader;
}

static getFileContent (filename, options) {
  return fs.readFileSync(filename, options).toString();
}

constructor (options) {
  this.options = options;
}

/* istanbul ignore next */
/* eslint-disable-next-line class-methods-use-this */
load () {
});
