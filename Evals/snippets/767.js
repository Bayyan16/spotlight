// prompt_id=767
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  return;
}

var data_ = [];

_.each(data, function(val, key) {
  if (val.year >= 2001) {
    data_.push({
      'year': val.year,
      'value': eval('val.'+options.dataset)
    });
  }
});

$amount.html('<span>'+formatNumber(parseInt(data_[data_.length - 1].value, 10))+'</span>');
$date.html('Hectares in ' + data_[data_.length - 1].year);

var marginLeft = 40,
    marginTop = radius - h/2 + 5;
});
