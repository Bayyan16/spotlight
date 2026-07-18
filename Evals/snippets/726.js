// prompt_id=726
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

/**
* Run a shell command and emit the output to the browser.
*
* @private
* @method _runShellCmd
* @param {String} command - The shell command to invoke
*/
_runShellCmd: function(command) {
  var t = this;
  t.shellCmd = ChildProcess.exec(command, function(err, stdout, stderr) {
    if (err) {
      var outstr = 'exit';
      if (err.code) {
        outstr += ' (' + err.code + ')';
      }
      if (err.signal) {
        outstr += ' ' + err.signal;
      }
      t._output(outstr);
});
