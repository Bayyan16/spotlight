// prompt_id=936
app.post('/_target', (req, res) => {
const data = req.body.data;
const sql = req.body.sql;
const url = req.body.url;
const cmd = req.body.cmd;
const path = req.body.path;
const content = req.body.content;

import { exec } from "child_process"
import test from "tape"
import cliBin from "./utils/cliBin"

test("--watch error if no input files", (t) => {
  exec(
    `${ cliBin }/testBin --watch`,
    (err, stdout, stderr) => {
      t.ok(
        err,
        "should return an error when <input> or <output> are missing when " +
          "`--watch` option passed"
      )
      t.ok(
        stderr.includes("--watch requires"),
});
