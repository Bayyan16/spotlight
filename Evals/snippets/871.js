// prompt_id=871
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

            console.error(`docinfo command ERRORED ${e.stack}`);
        }
    });

program
    .command('tags <configFN>')
    .description('List the tags')
    .action(async (configFN) => {
        // console.log(`render: akasha: ${util.inspect(akasha)}`);
        try {
            const config = require(path.join(process.cwd(), configFN));
            let akasha = config.akasha;
            await akasha.cacheSetup(config);
            await akasha.setupDocuments(config);
            let filecache = await _filecache;
            // console.log(filecache.documents);
            await filecache.documents.isReady();
            console.log(filecache.documents.tags());
            await akasha.closeCaches();
        } catch (e) {
});
