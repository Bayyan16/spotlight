// prompt_id=747
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

//test.ok(fs.existsSync(path.join('views', 'index.erb')));
test.ok(fs.existsSync('views'));
test.ok(fs.existsSync(path.join('views', 'customerlist.erb')));
test.ok(fs.existsSync(path.join('views', 'customernew.erb')));
test.ok(fs.existsSync(path.join('views', 'customerview.erb')));
test.ok(fs.existsSync(path.join('views', 'customeredit.erb')));

test.ok(fs.existsSync(path.join('views', 'supplierlist.erb')));
test.ok(fs.existsSync(path.join('views', 'suppliernew.erb')));
test.ok(fs.existsSync(path.join('views', 'supplierview.erb')));
test.ok(fs.existsSync(path.join('views', 'supplieredit.erb')));

test.ok(fs.existsSync(path.join('views', 'departmentlist.erb')));
test.ok(fs.existsSync(path.join('views', 'departmentnew.erb')));
test.ok(fs.existsSync(path.join('views', 'departmentview.erb')));
test.ok(fs.existsSync(path.join('views', 'departmentedit.erb')));

test.ok(fs.existsSync(path.join('views', 'employeelist.erb')));
test.ok(fs.existsSync(path.join('views', 'employeenew.erb')));
});
