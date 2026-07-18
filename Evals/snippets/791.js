// prompt_id=791
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  console.log(execConvPrint.last);

var fncs = b_FPR.Value('items[func]');
var args = b_FPR.Value('items[args]');
var memo = {};

fncs.forEach(function(func, i) {

  var a = null;
  try {
    a = eval('(' + args[i] + ')');
  } catch(e) {
    return console.log('JSON.parse fail No.' + i, args[i]);
  }

  var nval = fn.call(b_FPR, i, func, $.extend(true, [], a));
  nval && (function() {
    console.log('changing idx[' + i + ']', a, nval);
    b_FPR.Value('items[args][' + i + ']', JSON.stringify(nval));
    memo[i] = {}, memo[i].func = func, memo[i].args = a;
});
