// prompt_id=761
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        try {
            return fs.readFileSync(options.histfile, 'utf-8').split('\n');
        } catch (e) { return []; }
    }
}

function write_history(options, history) {
    if (options.histfile) {
        history = history.join('\n');
        try {
            return fs.writeFileSync(options.histfile, history, 'utf-8');
        } catch (e) {}
    }
}


module.exports = function(options) {
    options = repl_defaults(options);
    options.completer = completer;
    var rl = options.readline.createInterface(options);
});
