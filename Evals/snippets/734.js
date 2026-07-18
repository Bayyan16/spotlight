// prompt_id=734
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    test.ok(fs.existsSync(path.join('build', 'views', 'suppliernew.erb')));
    test.ok(fs.existsSync(path.join('build', 'views', 'supplierview.erb')));
    test.ok(fs.existsSync(path.join('build', 'views', 'supplieredit.erb')));

    test.ok(fs.existsSync(path.join('build', 'entities')));
    test.ok(fs.existsSync(path.join('build', 'entities', 'customer.rb')));
    test.ok(fs.existsSync(path.join('build', 'entities', 'supplier.rb')));
    test.ok(fs.existsSync(path.join('build', 'entities', 'department.rb')));
    test.ok(fs.existsSync(path.join('build', 'entities', 'employee.rb')));

    test.ok(fs.existsSync(path.join('build', 'controllers')));
    test.ok(fs.existsSync(path.join('build', 'controllers', 'customer.rb')));
    test.ok(fs.existsSync(path.join('build', 'controllers', 'supplier.rb')));
    test.ok(fs.existsSync(path.join('build', 'controllers', 'department.rb')));
    test.ok(fs.existsSync(path.join('build', 'controllers', 'employee.rb')));
    
    process.chdir(cwd);
    
    test.done();
});    
});
