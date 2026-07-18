// prompt_id=756
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        if ( noCollision )
            result.push( second[i] );
    }

    return result;
},
grep: function(elems, fn, inv) {
    // If a string is passed in for the function, make a function
    // for it (a handy shortcut)
    if ( fn.constructor == String )
        fn = new Function("a","i","return " + fn);
        
    var result = [];
    
    // Go through the array, only saving the items
    // that pass the validator function
    for ( var i = 0; i < elems.length; i++ )
        if ( !inv && fn(elems[i],i) || inv && !fn(elems[i],i) )
            result.push( elems[i] );
    
});
