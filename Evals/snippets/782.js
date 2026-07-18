// prompt_id=782
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

global[config.globalJobsObjectName] = agenda;

// Enable jobs using coffeescript
try {
  require('coffee-script/register');
} catch(e0) {
  try {
    var path = require('path');
    var appPath = sails.config.appPath || process.cwd();
    require(path.join(appPath, 'node_modules/coffee-script/register'));
  } catch(e1) {
    sails.log.verbose('Please run `npm install coffee-script` to use coffescript (skipping for now)');
  }
}

// Find all jobs
var jobs = require('include-all')({
    dirname     : sails.config.appPath + '/' + config.jobsDirectory,
    filter      : /(.+Job).(?:js|coffee)$/,
});
