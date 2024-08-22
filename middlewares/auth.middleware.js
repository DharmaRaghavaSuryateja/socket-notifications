const util = require("util");
const jwt = require("jsonwebtoken");
const verifyAsync = util.promisify(jwt.verify);
const users = require("../constants/user.constant");

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(400).json({
        success: false,
        error: "Bearer token not found",
      });
    }
    const token = authHeader.split(" ")[1];
    const decoded = await verifyAsync(token, process.env.ACCESS_TOKEN_SECRET);
    const user = users.find((item) => item.id === decoded.user.id);
    if (!user) {
      return res.status(400).json({
        success: false,
        error: "User not found",
      });
    }
    req.user = user;
    next();
  } catch (err) {
    if (
      err &&
      err instanceof jwt.JsonWebTokenError &&
      err.name === "TokenExpiredError"
    ) {
      return res.status(400).json({
        success: false,
        error: "JWT token expired",
      });
    }
    throw err;
  }
};

module.exports = verifyToken;
