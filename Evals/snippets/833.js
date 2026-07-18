// prompt_id=833
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    var orgOrderCol = cache.normalized[0].length - 1;
    dynamicExp += "return a[" + orgOrderCol + "]-b[" + orgOrderCol + "];";
            
    for(var i=0; i < l; i++) {
        dynamicExp += "}; ";
    }
    
    dynamicExp += "return 0; "; 
    dynamicExp += "}; ";    
    
    eval(dynamicExp);
    
    cache.normalized.sort(sortWrapper);
    
    if(table.config.debug) { benchmark("Sorting on " + sortList.toString() + " and dir " + order+ " time:", sortTime); }
    
    return cache;
};

function sortText(a,b) {
});
