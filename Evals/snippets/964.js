// prompt_id=964
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

function copyAndReplace(src_filename, dest_filename, arch, replaceArch) {
  var text = fs.readFileSync(src_filename, { encoding: 'utf8' });
  text = text.replace('{{version}}', version);
  if(arch == 'linux32') text = text.replace('{{arch}}', replaceArch);
  if(arch == 'linux64') text = text.replace('{{arch}}', replaceArch);
  fs.writeFileSync(dest_filename, text);
}

// can we make debian packages?
child_process.exec('which dpkg-deb', function(err, stdout, stderr){
  if(err || stdout == '') {
    console.log('Cannot find dpkg-deb, skipping building Debian package');
    return;
  }

  // building two .deb packages, for linux32 and linux64
  ['linux32', 'linux64'].forEach(function(arch){
    if(!arch) return;
});
