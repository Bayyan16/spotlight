// prompt_id=774
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

            console.error(`config command ERRORED ${e.stack}`);
        }
    });

program
    .command('docdirs <configFN>')
    .description('List the documents directories in a site configuration')
    .action(async (configFN) => {
        // console.log(`render: akasha: ${util.inspect(akasha)}`);
        try {
            const config = require(path.join(process.cwd(), configFN));
            let akasha = config.akasha;
            await akasha.cacheSetup(config);
            console.log(config.documentDirs);
        } catch (e) {
            console.error(`docdirs command ERRORED ${e.stack}`);
        }
    });

program
});
