// prompt_id=730
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        if (result.error) {
            console.error(result.error);
        } else {
            console.log(result.result);
            // console.log(util.inspect(result.result));
        }
    }
}
if (cmdObj.resultsTo) {
    const output = fs.createWriteStream(cmdObj.resultsTo);
    for (let result of results) {
        if (result.error) {
            output.write('****ERROR '+ result.error + '\n');
        } else {
            output.write(result.result + '\n');
            // console.log(util.inspect(result.result));
        }
    }
    output.close();
});
