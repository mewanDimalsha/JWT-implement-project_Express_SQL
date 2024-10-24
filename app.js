const express = require("express");
const cors = require("cors");
const router = require("./router");

const app = express();
const port = 3001;
const host = "localhost";

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use("/api", router);

app.listen(port, host, () => {
  console.log(`Server running on http://${host}:${port}`);
});

