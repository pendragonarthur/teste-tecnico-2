import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import mongoose from "mongoose";
import userModel from "./src/models/user-model.js";

const app = express();
const port = process.env.PORT;
const mongoUser = process.env.DB_USER;
const mongoPass = process.env.DB_PASS;
// Ativando o express para receber dados em JSON
app.use(express.json());
// Conectando no MongoDB
mongoose
  .connect(
    `mongodb+srv://${mongoUser}:${mongoPass}@cluster0.hoool0s.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(port);
    console.log(`Server is listening on http://localhost:${port}`);
  });

// Register User--------------------------------------------------------------------------------

app.post("/auth/register", async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  // Validação de dados
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Password not match" });
  }
  // Verifica se o usuário já existe
  const userExists = await userModel.findOne({ email: email });
  if (userExists) {
    return res.status(400).json({ error: "User already exists" });
  }
  // Criptografa a senha
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(password, salt);

  // Cria usuário
  const user = new userModel({
    username,
    email,
    password: hashPassword,
  });

  try {
    await user.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.log(error);
    return {
      status: 500,
      message: error.message,
    };
  }
});

// Login User-----------------------------------------------------------------

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  // Validação de dados
  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }
  if (!password) {
    return res.status(400).json({ error: "Password is required" });
  }
  // Verifica se o usuário existe
  const user = await userModel.findOne({ email: email });
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }
  // Verifica se a senha está correta
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: "Invalid password" });
  }
  // Cria e atribui um token
  try {
    const secret = process.env.SECRET;
    const token = jwt.sign({ _id: user._id }, secret);

    res.status(200).json({
      message: "User logged successfully",
      token: token,
    });
  } catch (error) {
    return {
      status: 500,
      message: error.message,
    };
  }
});

// Check Token-----------------------------------------------------------------
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  // Verifica se o token existe
  if (!token) {
    return res.status(401).json({ error: "Access denied" });
  }

  try {
    const secret = process.env.SECRET;
    const verified = jwt.verify(token, secret);
    req.userId = verified._id;
    next();
  } catch (error) {
    res.status(400).json({ error: "Invalid token" });
  }
}

// Rota Publica
app.get("/", (req, res) => {
  res.status(200).send("Hello World");
});

// Rota Privada
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // Verifica se o usuário existe
  const user = await userModel.findById(id, "-password");
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  res.status(200).json(user);
});
