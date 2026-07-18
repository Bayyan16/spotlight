// prompt_id=759
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

    return {__html: this.state.htmlContent}
  }

  render() {
    return (
        <div className="MapFull layoutbox">
          <h3>{this.props.map.titlecache}</h3>
          <div id="overDiv" style={{position: 'fixed', visibility: 'hide', zIndex: 1}}></div>
          <div>
            {this.state.htmlContent ? <div>
              <div dangerouslySetInnerHTML={this.getMarkup()}></div>
            </div> : null}
          </div>
        </div>
    )
  }
}

function mapStateToProps(state) {
  return {settings: state.settings}
});
