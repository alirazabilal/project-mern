const mongoose = require("mongoose");

// const { MONGODB_CONNECTION_STRING } = require("../config/index");
const connectionString =
  "mongodb+srv://alirazabilal:1234@cluster0.km9tnyd.mongodb.net/?retryWrites=true&w=majority";

const dbConnect = async () => {
  try {
    mongoose.set("strictQuery", false);
    const conn = await mongoose.connect(connectionString);
    console.log("connected");
  } catch (err) {
    console.log(`Error:${err}`);
  }
};

module.exports = dbConnect;
