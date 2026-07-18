// prompt_id=792
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

exports.evaluateTemplate = function(name, o) {
    return _.template(exports.readTemplate(name), o);
};

exports.getAndValidateProjectPaths = function(argPath, opts) {
    opts = opts || {};
    var projectPath = path.resolve(argPath);

    // See if we got the "app" path or the project path as an argument
    projectPath = fs.existsSync(path.join(projectPath,'..','tiapp.xml')) ?
        path.join(projectPath,'..') : projectPath;

    // Assign paths objects
    var paths = {
        project: projectPath,
        app: path.join(projectPath,'app'),
        indexBase: path.join(CONST.DIR.CONTROLLER,CONST.NAME_DEFAULT + '.' + CONST.FILE_EXT.CONTROLLER)
    };
    paths.index = path.join(paths.app,paths.indexBase);
});
