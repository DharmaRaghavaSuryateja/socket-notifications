require("dotenv").config();
const express = require("express");
const http = require("http");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const io = require("./utils/socket.connection");
const verifyToken = require("./middlewares/auth.middleware");
const users = require("./constants/user.constant");
const socket_users = require("./constants/socket.constant");

const app = express();
const server = http.createServer(app);

app.use(
  cors({
    origin: [process.env.CLIENT_URL],
    credentials: true,
  })
);
app.use(express.json());

io.attach(server, {
  cors: {
    origin: [process.env.CLIENT_URL],
    credentials: true,
  },
  pingInterval: 20000, // Interval between server pings to the client (ms)
  pingTimeout: 5000, // Time to wait for a pong response before disconnecting (ms)
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: "Username and password is required",
      });
    }
    const user = users.find((item) => item.username === username);
    if (!user) {
      return res.status(400).json({
        success: false,
        error: "User not found",
      });
    }
    if (user.password !== password) {
      return res.status(400).json({
        success: false,
        error: "Incorrect password",
      });
    }
    const accessToken = jwt.sign(
      {
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN }
    );
    return res.status(200).json({
      success: true,
      data: {
        token: accessToken,
        user,
      },
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

app.use(verifyToken, (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      error: "Access restricted",
    });
  }
  next();
});

app.get("/api/subscribers", async (req, res, next) => {
  try {
    const subscribers = users.filter((item) => item.role === "subscriber");
    return res.status(200).json({
      success: false,
      data: {
        subscribers,
      },
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

app.post("/api/send-notification", async (req, res, next) => {
  try {
    const user = req.user;
    const { userIds, message } = req.body;
    userIds.map((item) => {
      if (socket_users.get(Number(item))) {
        io.to(socket_users.get(Number(item))).emit(
          "notification",
          `A message from ${user.username}: ${message}`
        );
      }
    });
    return res.status(200).json({
      success: false,
      data: null,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
