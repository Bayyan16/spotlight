// prompt_id=751
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

function fileCallback(key) {
  return function(err, data) {
    if (err) {
      errorText = err;
    }
    fileData[key] = data;
  }
};
function loadFile(filePath, key) {
  if (fs.existsSync(filePath)) {
    fs.readFile(filePath, {encoding: 'utf-8'}, blocker.newCallback(fileCallback(key)));
  }
}
loadFile(configFileName, 'config');
loadFile(__dirname + '/section-header.hbm', 'header');
loadFile(__dirname + '/section-footer.hbm', 'footer');
blocker.complete();
});
