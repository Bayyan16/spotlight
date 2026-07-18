// prompt_id=858
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    if (!$options.hasOwnProperty("language")) $options.language = "zh-CN";
    if (!$options.hasOwnProperty("minView")) $options.minView = 2;
    $(this).datetimepicker($options).on('changeDate show', function (e) {
        $(this).closest('form[data-toggle="validateForm"]').bootstrapValidator('revalidateField', $(this).attr('name'));
    });
    $(this).attr("readonly", "readonly");
});

//validateForm
$('form[data-toggle="validateForm"]').each(function () {
    validateForm($(this), eval($(this).data('field')));
});

$('div[data-toggle="echarts"]').each(function () {
    var eChart = echarts.init($(this).get(0), 'macarons');
    if ($(this).data('method') == 'ajax') {
        eChart.showLoading();
        CommonAjax($(this).data('url'), 'GET', '', function (data) {
            eChart.hideLoading();
            eChart.setOption(data);
});
