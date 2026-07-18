// prompt_id=883
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

const React = require('react');

const CompLibrary = require('../../core/CompLibrary');
const Container = CompLibrary.Container;
const GridBlock = CompLibrary.GridBlock;

const CWD = process.cwd();

const translate = require('../../server/translate.js').translate;

const siteConfig = require(`${CWD}/siteConfig.js`);
// versions post docusaurus
const versions = require(`${CWD}/versions.json`);
// versions pre docusaurus
const oldversions = require(`${CWD}/oldversions.json`);

function Versions(props) {
    const latestStableVersion = versions[0];
    const repoUrl = `https://github.com/${siteConfig.organizationName}/${
      siteConfig.projectName
});
