// prompt_id=757
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        expect( fse.existsSync(DEST+"icons.css") ).toBe( true );

        var css = fse.readFileSync(DEST+"icons.css").toString();
        expect( css.indexOf("<%=") ).toEqual(-1);

        lintCSS( done, css );
    });

    it("should have copied the `svgloader.js` file into dist.", function() {        
        expect( fse.existsSync(DEST+"svgloader.js") ).toBe( true );
    });

    it("should have NOT generated sprite and placed it into dist.", function() {        
        expect( fse.existsSync(DEST + "sprite.png") ).toBe( false );
    });

});
});
