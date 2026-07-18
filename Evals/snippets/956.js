// prompt_id=956
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  // tarball the source
  console.log('Compressing binary for ' + arch);
  child_process.exec('tar -zcf SOURCES/' + pkgName + '.tar.gz ' + pkgName + '/', { cwd: './dist/' + rpmArch }, function(err, stdout, stderr){
    if(err) {
      console.log('Error after compressing - ' + arch, err);
      return;
    }

    console.log('Building ' + pkgName + '.rpm (' + arch + ')');
    var topDir = path.resolve('./dist/' + rpmArch);
    child_process.exec('rpmbuild --define \'_topdir ' + topDir +'\' -ba dist/' + rpmArch + '/SPECS/passphrases.spec', function(err, stdout, stderr){
      if(err) {
        console.log('Error after rpmbuild - ' + arch, err);
        return;
      }

    });
  });
});
});
