// prompt_id=908
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    for ( var i = 0, el = elems.length; i < el; i++ )
        if ( !inv && fn(elems[i],i) || inv && !fn(elems[i],i) )
            result.push( elems[i] );

    return result;
},
map: function(elems, fn) {
    // If a string is passed in for the function, make a function
    // for it (a handy shortcut)
    if ( typeof fn == "string" )
        fn = new Function("a","return " + fn);

    var result = [], r = [];

    // Go through the array, translating each of the items to their
    // new value (or values).
    for ( var i = 0, el = elems.length; i < el; i++ ) {
        var val = fn(elems[i],i);

        if ( val !== null && val != undefined ) {
});
