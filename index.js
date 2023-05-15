const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const User = require("./model/user");
const Todo = require("./model/todo");

const app = express();
const port = process.env.PORT || 3002;
const mongoUri = process.env.MONGO_URI;
const secret = process.env.SECRET;

mongoose
  .connect(mongoUri, {})
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.log(error));

// Define middleware to parse JSON
app.use(express.json());

// Define middleware to handle errors
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

// Define a middleware to authenticate user
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decodedToken = jwt.verify(token, secret);
    const userId = decodedToken.userId;
    const user = await User.findById(userId);
    if (!user) {
      throw new Error("Invalid token");
    }
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: "Authentication failed" });
  }
};

// Define a middleware to authorize user
const authorizeUser = (req, res, next) => {
  const userId = req.user._id;
  const todoUserId = req.body.userId || req.params.userId;
  if (userId.toString() !== todoUserId.toString()) {
    res.status(403).json({ error: "Authorization failed" });
  }
};

// Define the routes for users
app.post("/api/users", async (req, res) => {
  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    await user.save();
    res.status(201).json({ message: "User created" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/users/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      throw new Error("Invalid email or password");
    }
    const isPasswordMatched = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordMatched) {
      throw new Error("Invalid email or password");
    }
    const token = jwt.sign({ userId: user._id }, secret, { expiresIn: "1h" });
    res.status(200).json({ token: token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Define the routes for todos
app.get("/api/todos", authenticateUser, async (req, res) => {
  try {
    const userId = req.user._id;
    const skip = req.query.skip ? parseInt(req.query.skip) : 0;
    const limit = req.query.limit ? parseInt(req.query.limit) : 10;
    const sort = req.query.sort ? req.query.sort : "-createdAt";
    const filter = { userId: userId };
    if (req.query.search) {
      filter.title = { $regex: req.query.search, $options: "i" };
    }
    const count = await Todo.countDocuments(filter);
    const todos = await Todo.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .exec();
    res.status(200).json({ count: count, todos: todos });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/todos", authenticateUser, async (req, res) => {
  try {
    const todo = new Todo({
      title: req.body.title,
      description: req.body.description,
      completed: req.body.completed || false,
      userId: req.user._id,
    });
    await todo.save();
    res.status(201).json({ message: "Todo created" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/api/todos/:id", authenticateUser, async (req, res) => {
  try {
    const todo = await Todo.findOne({
      _id: req.params.id,
      userId: req.user._id,
    });
    if (!todo) {
      throw new Error("Todo not found");
    }
    res.status(200).json({ todo: todo });
  } catch (error) {
    res.status(404).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
