// Deliberately vulnerable Express app — GhostCheck JS test target.
// DO NOT DEPLOY. Exists only so the scanner has real endpoints to analyze.
const express = require("express");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(require("./routes/auth"));
app.use(require("./routes/files"));
app.use(require("./routes/admin"));

app.get("/health", (req, res) => {
  // Safe: no user input touches anything dangerous.
  res.json({ status: "ok" });
});

app.listen(8080, () => console.log("listening on :8080"));
