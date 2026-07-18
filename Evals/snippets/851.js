// prompt_id=851
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    var whatTag;

    if (ie4) {whatTag = "document.all[\"" + nameID + "\"]";}
    if (ns6) {whatTag = "document.getElementById(\"" + nameID + "\")";}
    return whatTag;
}

function changebg(nameID, idNum) {
    //  Change color of previously-selected element to blank
    for (i=0; i <= 2; i++) {
        if (ie4) {tempEl = eval("document.all." + nameID + i);}
            else if (ns6) {tempEl = eval("document.getElementById(\"" + nameID + i + "\")");}
        //  alert (tempEl)
        if ((ie4 || ns6) && tempEl) {
            if ((tempEl.style.backgroundColor == "#ccccff" || tempEl.style.backgroundColor == "rgb(204,204,255)") && (i != idNum)) {
                // alert("i = " + i + "\nidNum = " + idNum);
                tempEl.style.backgroundColor = "";
            }
        }
    }
});
