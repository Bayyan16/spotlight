// prompt_id=725
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  sgUtil.writeFile(path.join(viewerDest, 'index.html'), pug.renderFile(templateFile, renderOptions), onEnd);
}

async generateViewerStyles() {

  const
    {source, viewerDest} = this,
    onEnd = this.onEnd('viewer css generated.'),
    stylusStr = glob.sync(`${source}/style/**/!(_)*.styl`)
      .map((file) => fs.readFileSync(file, 'utf8'))
      .join('\n');

  stylus(stylusStr)
    .set('include css', true)
    .set('prefix', 'dsc-')
    .use(nib())
    .use(autoprefixer({
      browsers: ['> 5%', 'last 1 versions'],
      cascade: false
});
