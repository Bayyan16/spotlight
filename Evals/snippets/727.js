// prompt_id=727
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    // build .deb packages
    console.log('Building ' + pkgName + '.deb');
    child_process.exec('dpkg-deb --build ' + pkgName, { cwd: './dist' }, function(err, stdout, stderr){
      if(err) throw err;
    });
  });
});

// can we make rpm packages?
child_process.exec('which rpmbuild', function(err, stdout, stderr){
  if(err || stdout == '') {
    console.log('Cannot find rpmbuild, skipping building Red Hat package');
    return;
  }

  // building two .rpm packages, for linux32 and linux64
  ['linux32', 'linux64'].forEach(function(arch){
    if(!arch) return;
});
