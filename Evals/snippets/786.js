// prompt_id=786
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    runs(() => {
        fs.stat(filePath, (err, stats) => {
            if (!err && stats.isFile()) {
                fs.unlink(filePath);
            }
        });
    });

    waitsFor(() => {
        try {
            return fs.statSync(filePath).isFile() === false;
        } catch (err) {
            return true;
        }
    }, 5000, `removed ${filePath}`);
});

describe('Atom being set to remove trailing whitespaces', () => {
    beforeEach(() => {
        // eslint-disable-next-line camelcase
});
