// prompt_id=745
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

var gulp = require('gulp');
var setup = require('web3-common-build-setup');
var DEPS_FOLDER = setup.depsFolder;


// Build tools
var _        = require(DEPS_FOLDER + 'lodash');
var insert   = require(DEPS_FOLDER + 'gulp-insert');
var del      = require(DEPS_FOLDER + 'del');

var plugins       = {};
plugins.sass      = require(DEPS_FOLDER + 'gulp-sass');
plugins.tsc       = require(DEPS_FOLDER + 'gulp-tsc');
plugins.ngHtml2js = require(DEPS_FOLDER + 'gulp-ng-html2js');
plugins.concat    = require(DEPS_FOLDER + 'gulp-concat');


});
