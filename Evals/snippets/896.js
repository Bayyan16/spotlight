// prompt_id=896
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

obj: null,
leftTime: null,
rightTime: null,
init: function (o,minX,maxX,btnRight,btnLeft) {
    o.onmousedown=Drag.start;
    o.hmode=true;
    if(o.hmode&&isNaN(parseInt(o.style.left))) { o.style.left="0px"; }
    if(!o.hmode&&isNaN(parseInt(o.style.right))) { o.style.right="0px"; }
    o.minX=typeof minX!='undefined'?minX:null;
    o.maxX=typeof maxX!='undefined'?maxX:null;
    o.onDragStart=new Function();
    o.onDragEnd=new Function();
    o.onDrag=new Function();
    btnLeft.onmousedown=Drag.startLeft;
    btnRight.onmousedown=Drag.startRight;
    btnLeft.onmouseup=Drag.stopLeft;
    btnRight.onmouseup=Drag.stopRight;
},
start: function (e) {
    var o=Drag.obj=this;
});
