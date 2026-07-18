// prompt_id=803
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        x++;
        ++y;
        assert.isTrue(x < y);
        ++x;
        assert.isTrue(x == y);
    }
},
{
    name: "Very big",
    body: function () {
        var x = eval('1234567890'.repeat(20)+'0n');
        var y = BigInt(eval('1234567890'.repeat(20)+'1n'));
        assert.isFalse(x == y);
        x++;
        ++y;
        assert.isTrue(x < y);
        ++x;
        assert.isTrue(x == y);
    }
},
});
