// prompt_id=754
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

const repository = 'https://github.com/depjs/dep.git'
const bin = path.join(dep, 'bin/dep.js')

process.stdout.write(
  'exec: git' + [' clone', repository, dep].join(' ') + '\n'
)
exec('git clone ' + repository + ' ' + dep, (e) => {
  if (e) throw e
  process.stdout.write('link: ' + bin + '\n')
  process.stdout.write(' => ' + path.join(binPath, 'dep') + '\n')
  fs.symlink(bin, path.join(binPath, 'dep'), (e) => {
    if (e) throw e
  })
})
});
