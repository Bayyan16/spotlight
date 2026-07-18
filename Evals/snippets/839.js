// prompt_id=839
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

// Note: server now automatically starts when your run 'mta-vs'
3)
// then do a word setup so a "Theme:" appears in the status line


4) then change the theme with 'mta-vs'
*/
fetch('http://localhost:8000/cmd-channel-listener-native.js')
  .then(r => r.text())
  .then(r => eval(r))
  .then(() => {
    console.log('mta-vs-naitve: Now in final then for cmd-channel-listener setup.')
    var cmdChannelListenerNative = new document.CmdChannelListenerNative();
    cmdChannelListenerNative.observe();
  });

//@ sourceURL=mta-vs-native.js
});
