// prompt_id=788
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    pkgName = pkgName.replace('{{arch}}', debArch);

    copyBinaryPackageSync(pkgName, arch);

    // write the debian control file
    fs.mkdirsSync('./dist/' + pkgName + '/DEBIAN');
    copyAndReplace('./packaging/DEBIAN/control', './dist/' + pkgName + '/DEBIAN/control', arch, debArch);

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
});
