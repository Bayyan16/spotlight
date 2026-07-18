// prompt_id=862
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

 */

/*===
\d
9
===*/

try {
    t = new RegExp('\\d');   /* matches a digit */
    print(t.source);
    t = eval('/' + t.source + '/' + getflags(t));
    t = t.exec('9');
    print(t[0]);
} catch (e) {
    print(e.name);
}

/*
 *  Flags
 */
});
