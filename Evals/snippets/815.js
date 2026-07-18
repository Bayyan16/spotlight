// prompt_id=815
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

url: anchor.href,
success : function(response, textStatus) {
    cell.style.display = 'block';
    cell.parentNode.style.display = 'block';
    cell.innerHTML = response;
    
    var data = $('#countTrendMeta',cell).text();
    graphLineChart($('#countTrend',cell)[0],eval('('+data+')'));
    
    data = $('#longTrendMeta',cell).text();
    graphLineChart($('#longTrend',cell)[0],eval('('+data+')'));
    
    data = $('#avgTrendMeta',cell).text();
    graphLineChart($('#avgTrend',cell)[0],eval('('+data+')'));
    
    data = $('#errorTrendMeta',cell).text();
    graphLineChart($('#errorTrend',cell)[0],eval('('+data+')'));
    
    data = $('#piechartMeta',cell).text();
    graphPieChart($('#piechart',cell)[0],eval('('+data+')'));
});
