const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();
app.get("/run", (req, res) => {
  const cmd = "ls " + req.query.dir;
  exec(cmd);
  const id = parseInt(req.query.id);
  db.query("SELECT * FROM t WHERE id = " + id);
  res.send("<h1>" + req.query.name + "</h1>");
  fs.readFile(req.params.file, () => {});
});
