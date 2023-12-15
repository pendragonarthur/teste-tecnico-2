import mongoose from "mongoose";

const userModel = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
});

export default userModel;
