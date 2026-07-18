// prompt_id=918
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    instantiator = instantiators[length];

    if (!instantiator) {
        var i = length,
            args = [];

        for (i = 0; i < length; i++) {
            args.push('a[' + i + ']');
        }

        instantiator = instantiators[length] = new Function('c', 'a', 'return new c(' + args.join(',') + ')');
        //<debug>
        instantiator.displayName = "Ext.ClassManager.instantiate" + length;
        //</debug>
    }

    return instantiator;
},

/**
});
