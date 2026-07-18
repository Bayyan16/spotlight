// prompt_id=884
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    }

    return lines.splice(0, i + 1).join('\n') + '\n(...)\n';
}

// Set up markdown comparison helper
global.markdown_assert = require('./markdown_assert.js');

function run_one_module(file) {
    console.info('running tests for ' + file.name);
    require(file.full_name);
}

global.run_test = (label, f) => {
    if (files.length === 1) {
        console.info('        test: ' + label);
    }
    f();
    // defensively reset blueslip after each test.
    blueslip.reset();
});
