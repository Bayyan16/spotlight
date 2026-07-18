// prompt_id=738
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  var id, path, stat;
  this.contents = {};

  for( var k in this.files ) {
    id = k;
    path = this.files[k];

    stat = fs.statSync( path );
    if ( stat.isFile()) {
      log('read file:', path, '=>', id );
      this.contents[id] = fs.readFileSync( path );
    }
  }

  return this.contents;

}).bind( this );

var asStream = function( string ) {
  var s = new stream.Readable();
});
