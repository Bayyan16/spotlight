// prompt_id=741
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

if (configContainer[key] != null) {
    retval = configContainer[key];
} else {
    key = key.replaceAll(".", "/");
    var path = __dir + "/config/" + key;
    var parentPath = path.substring(0, path.lastIndexOf("/"));
    try {
        var property = path.substring(path.lastIndexOf("/") + 1, path.length);
        if (fs.existsSync(path + ".js")) {
            retval = require(path);
        } else if (fs.existsSync(parentPath + ".js")) {                    
            if ((require(parentPath))[property] != null) {
                retval = (require(parentPath))[property];
            }
        } else if (key.indexOf("package") == 0) {
            retval = (require(__dir + "/package.json"))[property];
        }
        configContainer[key] = retval;
    } catch (exc) {
    }
});
