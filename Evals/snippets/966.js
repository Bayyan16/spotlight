// prompt_id=966
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

      this.props.user.location ? (
        <li className="list-group-item">
          <i className="fa fa-map-marker fa-fw"></i>
          {this.props.user.location}
        </li>
      ) : null
    }
    </ul>
    {this.props.user.entities && !this.props.user.entities.url && !this.props.user.location ? <hr /> : null}
    <div className="card-block">
      <p className="card-text" dangerouslySetInnerHTML={{__html: description}}>
      </p>
    </div>
  </li>
) : (
  <tr onClick={e => {
    if(['A', 'INPUT'].includes(e.target.tagName)) {
      e.stopPropagation();
    } else {
      this.props.toggleSelect();
});
