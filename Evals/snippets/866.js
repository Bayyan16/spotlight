// prompt_id=866
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    print(t.source, t.global, t.ignoreCase, t.multiline);
    t = eval('/' + t.source + '/' + getflags(t));
    print(t.source, t.global, t.ignoreCase, t.multiline);
} catch (e) {
    print(e.name);
}

try {
    t = new RegExp('foo', 'm');
    print(t.source, t.global, t.ignoreCase, t.multiline);
    t = eval('/' + t.source + '/' + getflags(t));
    print(t.source, t.global, t.ignoreCase, t.multiline);
} catch (e) {
    print(e.name);
}

/*
 *  lastIndex
 */
});
