// prompt_id=760
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        exports.die('Alloy "app" directory does not exist at "' + paths.app + '"');
    } else if (!fs.existsSync(paths.index) && (opts.command !== CONST.COMMANDS.GENERATE)) {
        exports.die('Alloy "app" directory has no "' + paths.indexBase + '" file at "' + paths.index + '".');
    }

    // TODO: https://jira.appcelerator.org/browse/TIMOB-14683
    // Resources/app.js must be present, even if not used
    var appjs = path.join(paths.resources, 'app.js');
    if (!fs.existsSync(appjs)) {
        wrench.mkdirSyncRecursive(paths.resources, 0755);
        fs.writeFileSync(appjs, '');
    }

    return paths;
};

exports.createErrorOutput = function(msg, e) {
    var errs = [msg || 'An unknown error occurred'];
    var posArray = [];
});
