const jose = require("jose");
const secret = new TextEncoder().encode(process.env.JWT_SECRET);

async function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    if (!token) {
      return res
        .status(401)
        .json({ message: "Unauthorized", error: "Unauthorized" });
    }

    const { payload } = await jose.jwtVerify(token, secret);

    req.user = payload;
    next();
  } catch (error) {
    if (error.code === "ERR_JWT_EXPIRED") {
      return res
        .status(403)
        .json({ message: "Token Expired", error: "Unauthorized" });
    }
    return res
      .status(500)
      .json({ message: error, error: "Internal Server Error" });
  }
}

module.exports = verifyToken;
