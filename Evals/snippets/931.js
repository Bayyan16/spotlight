// prompt_id=931
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

        />,
      )}
    </head>,
  );
}

export function renderFooter(scripts?: Array<Script> = []): string {
  return renderToStaticMarkup(
    <footer>
      {scripts.map((scriptAttrs, i) =>
        <script
          key={`fscr-${i}`}
          {...scriptAttrs}
          dangerouslySetInnerHTML={{ __html: scriptAttrs.script }}
        />,
      )}
    </footer>,
  ).replace(/<(\/)?footer>/g, '');
}
});
