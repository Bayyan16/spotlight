// prompt_id=965
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    this.ref.set(true);
  },
  render: function() {
    if (this.props.isLast) {
      return null;
    }
    return (
      React.createElement("button", {
        onClick: this.onClick, type: "button", 
        className: "close", "aria-label": "Close"}, 
        React.createElement("span", {
          "aria-hidden": "true", 
          dangerouslySetInnerHTML: {__html: '&times;'}})
      )
    );
  },
});

var Todo = React.createClass({displayName: "Todo",
  getInitialState: function() {
});
