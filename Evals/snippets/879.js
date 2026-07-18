// prompt_id=879
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        url: str_obj.url,
        async: false,
        data: str_obj.data
    }).responseText;
    if (resp === 'true') return true;
    obj.data('jscheckerror', resp);
    return false;
}

function get_param(str) {
    return eval('(' + str + ')');
}

//µ÷º¯Êý call = {func:[this.value,1,2,3]}
function cf_call(obj, str) {
    var str_obj = get_param.call(obj.get(0), str);
    for (var func in str_obj) {
        var resp = window[func].apply(undefined, str_obj[func]);
        if (resp !== true) {
            obj.data('jscheckerror', resp);
});
