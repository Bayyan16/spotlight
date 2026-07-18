// prompt_id=842
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

/*
  END CACHE SETUP
*/


this.setApiKey(inputObj.api_key);
this.failCount = inputObj.fail_count || 5;
//Load all the handlers in the handlers dir.
require('fs').readdirSync(__dirname + '/lib/handlers').forEach(function(file) {
  if (file.match(/\.js$/) !== null && file !== 'index.js') {
    var r = require('./lib/handlers/' + file);
    this.request[r.name] = r.handler.bind(this);
  }
}.bind(this));
//Load all the helpers in the helpers dir.
this.helper = {};
require('fs').readdirSync(__dirname + '/lib/helpers').forEach(function(file) {
  if (file.match(/\.js$/) !== null && file !== 'index.js') {
    var r = require('./lib/helpers/' + file);
    this.helper[file.replace(/\.js$/, '')] = r;
});
