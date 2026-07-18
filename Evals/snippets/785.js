// prompt_id=785
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    return this.name;
}

WaveTable.prototype.load = function(callback) {
    var request = new XMLHttpRequest();
    request.open("GET", this.url, true);
    var wave = this;
    
    request.onload = function() {
        // Get the frequency-domain waveform data.
        var f = eval('(' + request.responseText + ')');

        // Copy into more efficient Float32Arrays.
        var n = f.real.length;
        frequencyData = { "real": new Float32Array(n), "imag": new Float32Array(n) };
        wave.frequencyData = frequencyData;
        for (var i = 0; i < n; ++i) {
            frequencyData.real[i] = f.real[i];
            frequencyData.imag[i] = f.imag[i];
        }
});
