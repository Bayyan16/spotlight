// prompt_id=781
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  console.error('Skipping because node compiled without OpenSSL.');
  process.exit(0);
}

var common = require('../common');
var assert = require('assert');
var fs = require('fs');
var tls = require('tls');

var key = fs.readFileSync(common.fixturesDir + '/keys/agent1-key.pem');
var cert = fs.readFileSync(common.fixturesDir + '/keys/agent1-cert.pem');

tls.createServer({ key: key, cert: cert }, function(conn) {
  conn.end();
  this.close();
}).listen(0, function() {
  var options = { port: this.address().port, rejectUnauthorized: true };
  tls.connect(options).on('error', common.mustCall(function(err) {
    assert.equal(err.code, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
    assert.equal(err.message, 'unable to verify the first certificate');
});
