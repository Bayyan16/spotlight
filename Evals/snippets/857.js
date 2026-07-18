// prompt_id=857
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    if(httpServer) {
        this.emit('ready');
    };
    cb && cb(httpServer);
}

LHServer.prototype.set = function(option, value) {
    this.options[option] = value;
    if(option === 'view engine' && value && value !== '') {
        try {
            this.viewEngine = require(value);
        } catch (err) {
            this.emit('error',err);
        }
    }
}

LHServer.prototype.getFunctionList = function(requestPath, method) {
    var ret = [];
    if(this.options['static']) {
});
