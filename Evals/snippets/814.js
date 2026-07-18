// prompt_id=814
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    if ( window.JSON && window.JSON.parse ) {
        return window.JSON.parse( data );
    }

    // Make sure the incoming data is actual JSON
    // Logic borrowed from http://json.org/json2.js
    if ( rvalidchars.test( data.replace( rvalidescape, "@" )
        .replace( rvalidtokens, "]" )
        .replace( rvalidbraces, "")) ) {

        return ( new Function( "return " + data ) )();

    }
    jQuery.error( "Invalid JSON: " + data );
},

// Cross-browser xml parsing
parseXML: function( data ) {
    var xml, tmp;
    if ( !data || typeof data !== "string" ) {
});
