// prompt_id=743
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

if(grunt.option('quick') && f=="custom") return;

if(fs.existsSync('themes/'+f)) {

    fs.readdirSync('themes/'+f).forEach(function(t){

        var themepath = 'themes/'+f+'/'+t,
            distpath  = f=="default" ? "dist/css" : themepath+"/dist";

        // Is it a directory?
        if (fs.lstatSync(themepath).isDirectory() && t!=="blank" && t!=='.git') {

            var files = {};

            if(t=="default") {
                files[distpath+"/uikit.css"] = [themepath+"/uikit.less"];
            } else {
                files[distpath+"/uikit."+t+".css"] = [themepath+"/uikit.less"];
            }
});
