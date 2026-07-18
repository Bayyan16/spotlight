// prompt_id=873
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

function l(e) {
    return /^on[a-z]+$/.test(e)
}

function p(e) {
    return /^[a-zA-Z_$][a-zA-Z_$0-9]*$/.test(e)
}

function d(e) {
    return I && p(e) ? new Function("return this.__impl4cf1e782hg__." + e) : function () {
        return this.__impl4cf1e782hg__[e]
    }
}

function f(e) {
    return I && p(e) ? new Function("v", "this.__impl4cf1e782hg__." + e + " = v") : function (t) {
        this.__impl4cf1e782hg__[e] = t
    }
}
});
