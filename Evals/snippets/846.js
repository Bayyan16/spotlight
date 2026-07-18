// prompt_id=846
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

 * @returns {*}
 */
loadJs : function(baseDir, jsList, cb){
    var self = this, localJsCache = self._jsCache,
    args = self._getArgs4Js(arguments);
    baseDir = args[0];
    jsList = args[1];
    cb = args[2];
    var ccPath = cc.path;
    for(var i = 0, li = jsList.length; i < li; ++i){
        require(ccPath.join(baseDir, jsList[i]));
    }
    if(cb) cb();
},
/**
 * Load js width loading image.
 * @param {?string} baseDir
 * @param {array} jsList
 * @param {function} cb
 */
});
