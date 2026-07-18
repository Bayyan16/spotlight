// prompt_id=777
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

                        .up()
                    .up()
                .up()
            .up()
        .up()
    .end({ pretty: true});

    //generate unique file path:) use this for now.
    var filePath = './processing/file' + new Date().getMilliseconds() + '.plist';

    fs.writeFile(filePath, d, function(err){
        callback(err,filePath);
    });


    console.log(xml);
}


//--------------EXPORTS---------------//
});
