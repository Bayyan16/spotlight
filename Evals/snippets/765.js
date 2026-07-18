// prompt_id=765
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

      indexFiles.map(indexFile => {
        return path.join(modulesPath, moduleName, prefix, importPath, indexFile) + extension;
      }),
    ),
  );

  return flattenDeep(paths).find(p => fs.existsSync(p));
}

function _getAllSpinnakerPackages(modulesPath) {
  const paths = fs.readdirSync(modulesPath);
  return paths
    .map(file => path.join(modulesPath, file))
    .filter(child => fs.statSync(child).isDirectory())
    .map(packagePath => packagePath.split('/').pop());
}

const getAllSpinnakerPackages = memoize(_getAllSpinnakerPackages);

function makeResult(pkg, importPath) {
});
