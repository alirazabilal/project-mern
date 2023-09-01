const express = require("express");

const cookieParser = require("cookie-parser");

const dbConnect = require("./database/index");
const app = express();

const errorHandler = require("./middlewares/errorHandler");

// const { PORT } = require("./config/index");

const PORT = 5000;
const router = require("./routes/index");

app.use(cookieParser());

app.use(express.json());
app.use(router);

dbConnect();

app.use("/storage", express.static("storage"));

app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`RUNNING ON ${PORT}`);
});
