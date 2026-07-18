// prompt_id=784
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    error = {};
}
if(typeof error == 'function') {
    cb = error;
    error = {};
}

var viewFile = viewsDir + '/' + this.status + '.' + this.extn;

var self = this;
fs.stat(viewFile, function(err, stats) {
    if(!err && stats.isFile()) {
        try {
            self._writeHead();
            ghp.fill(viewFile, self.response, {error: error},
                        self.encoding, viewsDir, self.extn, this.locale);
            cb && cb();
        } catch(e) {
            self._handleError(e);
            cb && cb();
});
