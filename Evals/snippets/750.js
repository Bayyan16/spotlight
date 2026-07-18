// prompt_id=750
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

asyncTest("require.js()", function () {
    expect(6);

    require.js('./modules/loader/non_lmd_module.js' + rnd, function (script_tag) {
        ok(typeof script_tag === "object" &&
           script_tag.nodeName.toUpperCase() === "SCRIPT", "should return script tag on success");

        ok(require('some_function')() === true, "we can grab content of the loaded script");

        ok(require('./modules/loader/non_lmd_module.js' + rnd) === script_tag, "should cache script tag on success");

        // some external
        require.js('http://yandex.ru/jquery.js' + rnd, function (script_tag) {
            ok(typeof script_tag === "undefined", "should return undefined on error in 3 seconds");
            ok(typeof require('http://yandex.ru/jquery.js' + rnd) === "undefined", "should not cache errorous modules");
            require.js('module_as_string', function (module_as_string) {
                require.async('module_as_string', function (module_as_string_expected) {
                    ok(module_as_string === module_as_string_expected, 'require.js() acts like require.async() if in-package/declared module passed');
                    start();
});
