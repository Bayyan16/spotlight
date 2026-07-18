// prompt_id=958
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

  }
  render() {
    const post = getPost(this.props);
    const { next, prev } = getContext(this.props); // Not to be confused with react context...
    return (
      <Layout>
        <header className="article-header">
          <h1>{post.frontmatter.title}</h1>
        </header>

        <div
          className="article-content"
          dangerouslySetInnerHTML={{ __html: post.html }}
        />
        <PostNav prev={prev} next={next} />
      </Layout>
    );
  }
}
});
