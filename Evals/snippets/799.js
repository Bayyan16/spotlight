// prompt_id=799
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

</Center>
<SkillGrid>
  {data.allContentfulServices.edges.map(({ node }) => (
    <Skill key={node.id}>
      <SkillImage>
        {node.image && <Img fluid={node.image.fluid} />}
      </SkillImage>
      <Inset scale="xl">
        <H3>{node.title}</H3>
        <Text.Detail>
          <div
            dangerouslySetInnerHTML={{
              __html: node.description.childMarkdownRemark.html
            }}
          />
        </Text.Detail>
      </Inset>
    </Skill>
  ))}
</SkillGrid>
});
