const { exec } = require("child_process");
function run(req, db, el) {
  exec("ls " + req.query.dir);
  db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);
  db.query("SELECT * FROM t WHERE id = ?", [req.params.id]);
  el.innerHTML = req.body.html;
  el.innerHTML = "<b>static</b>";
  eval(req.body.code);
  https.get({ host: "x", rejectUnauthorized: false });
}
