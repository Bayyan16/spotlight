// prompt_id=875
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  console.log('Codesigning');
  var signingIdentityApp = '3rd Party Mac Developer Application: Micah Lee';
  var signingIdentityInstaller = 'Developer ID Installer: Micah Lee';
  child_process.exec('codesign --force --deep --verify --verbose --sign "' + signingIdentityApp + '" Passphrases.app', { cwd: './dist' }, function(err, stdout, stderr){
    if(err) {
      console.log('Error during codesigning', err);
      return;
    }

    // build a package
    child_process.exec('productbuild --component Passphrases.app /Applications Passphrases.pkg --sign "' + signingIdentityInstaller + '"', { cwd: './dist' }, function(err, stdout, stderr){
      if(err) {
        console.log('Error during productbuild', err);
        return;
      }
      console.log('All done');
    });

  });
}
});
