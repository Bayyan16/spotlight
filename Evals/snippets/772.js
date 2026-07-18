// prompt_id=772
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

var _ = require('lodash'),
    restify = require('restify'),
    async = require('async');


module.exports = function(settings, server, db){

    var globalLogger = require(settings.path.root('logger'));
    var auth = require(settings.path.lib('auth'))(settings, db);
    var api = require(settings.path.lib('api'))(settings, db);

    var vAlpha = function(path){ return {path: path, version: settings.get("versions:alpha")} };

    function context(req){
        return {logger: req.log};
    }

    server.get(vAlpha('/ping'), function(req, res, next){
});
