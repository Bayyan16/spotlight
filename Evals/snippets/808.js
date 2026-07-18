// prompt_id=808
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

// *    uploads image by providing a link by running:
// *    enduro upload http://www.imgur.com/asd.png
// * ———————————————————————————————————————————————————————— * //
var cli_upload = function () {}

// vendor dependencies
var Promise = require('bluebird')

// local dependencies
var logger = require(ENDURO_FOLDER + '/libs/logger')
var file_uploader = require(ENDURO_FOLDER + '/libs/admin_utilities/file_uploader')

// * ———————————————————————————————————————————————————————— * //
// *    cli upload
// *    generates object based on flag array
// *
// *    @return {string} - url for uploaded link
// * ———————————————————————————————————————————————————————— * //
cli_upload.prototype.cli_upload = function (file_url) {
    if (!file_url) {
});
