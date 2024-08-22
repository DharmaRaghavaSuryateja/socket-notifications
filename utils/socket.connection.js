const util = require("util");
const jwt = require("jsonwebtoken");
const verifyAsync = util.promisify(jwt.verify);
const socket = require("socket.io");
const { RateLimiterMemory } = require("rate-limiter-flexible");
const socket_users = require("../constants/socket.constant");
const users = require("../constants/user.constant");

const io = socket();

const rate_limit = new RateLimiterMemory({
  points: 60,
  duration: 60,
});

io.use(async (socket, next) => {
  try {
    const bearerToken = socket?.handshake?.query?.token;
    const ip = socket?.handshake?.address;
    await rate_limit.consume(ip, 1);
    if (!bearerToken?.startsWith("Bearer ")) {
      return next(new Error("Bearer token not found"));
    }
    const token = bearerToken.split(" ")[1];
    const decoded = await verifyAsync(token, process.env.ACCESS_TOKEN_SECRET);
    const user = users.find((item) => item.id === decoded.user.id);
    const user_id = user?.id;
    if (user_id) {
      socket.user_id = user_id;
      socket_users.set(user_id, socket.id);
      return next();
    } else {
      return next(new Error("Socket authentication error"));
    }
  } catch (error) {
    if (
      error &&
      error instanceof jwt.JsonWebTokenError &&
      error.name === "TokenExpiredError"
    ) {
      return next(new Error("JWT token expired"));
    }
    if (error?.remainingPoints !== undefined && error?.remainingPoints === 0) {
      return next(new Error("Too Many Requests"));
    }
    return next(new Error("Socket internal server error"));
  }
});

io.on("connection", (socket) => {
  console.log(`User ${socket?.user_id} with socket id ${socket?.id} connected`);
  socket.on("disconnect", () => {
    if (socket.user_id) {
      socket_users.delete(socket.user_id);
      console.log(
        `User ${socket?.user_id} with socket id ${socket?.id} disconnected`
      );
    }
  });
  socket.on("error", (error) => {
    console.log(
      `User ${socket?.user_id} with socket id ${socket?.id} error: ${error.message}`
    );
  });
});

module.exports = io;
