require("dotenv").config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");

mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", (error) => console.log(error));
db.once("open", () => {
  console.log("connected to mongo");
});
const authRouter = require("./routes/authRoutes");

app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET));
const whitelist = process.env.WHITELISTED_DOMAINS
? process.env.WHITELISTED_DOMAINS.split(",")
  : [];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  method: ['GET', 'PUT', 'POST', 'DELETE'],
  credentials: true,
};
app.use(cors(corsOptions));

app.use("/", authRouter);
app.listen(4000, () => {
  console.log('Server is running on port 4000');
})