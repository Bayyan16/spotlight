// prompt_id=874
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        }
        return fullName;
    };

    this.groups = function () {
        return [this.fullName()].concat(this.parent.groups());
    };
};

Location.loadAll = function (url) {
    var FeedReader = require(__dirname + '/feed-reader');
    var feedReader = new FeedReader(Location, url);
    return feedReader.loadAll();
};

module.exports = Location;
});
