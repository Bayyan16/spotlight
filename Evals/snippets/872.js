// prompt_id=872
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;


// Build tools
var _        = require(DEPS_FOLDER + 'lodash');
var insert   = require(DEPS_FOLDER + 'gulp-insert');
var del      = require(DEPS_FOLDER + 'del');

var plugins       = {};
plugins.sass      = require(DEPS_FOLDER + 'gulp-sass');
plugins.tsc       = require(DEPS_FOLDER + 'gulp-tsc');
plugins.ngHtml2js = require(DEPS_FOLDER + 'gulp-ng-html2js');
plugins.concat    = require(DEPS_FOLDER + 'gulp-concat');


// Customize build configuration
var CONFIG = setup.buildConfig;
CONFIG.FOLDER.APP = _.constant("./src/app/web3-demo/");

CONFIG.PARTIALS.MAIN = function() {
    return [
        "./src/app/web3-demo/view/content.html"
});
