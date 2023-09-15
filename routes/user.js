const { PrismaClient } = require("@prisma/client");
const express = require("express");
const hashPassword = require("../utils/passwordHash");
const verifyToken = require("../middleware/verifyToken");
const jose = require("jose");
const bcrypt = require("bcryptjs");
const router = express.Router();
const prisma = new PrismaClient();
const secret = new TextEncoder().encode(process.env.JWT_SECRET);

console.log(secret);

router.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({
      message: "Please provide all the required field",
      error: "Bad Request",
    });
  }

  const { hash, salt } = await hashPassword(password, res);

  await prisma.user
    .create({
      data: {
        username,
        password: hash,
        email,
        salt,
      },
    })
    .then((_) => {
      return res.status(201).json({ message: "User created" });
    })
    .catch((error) => {
      if (error.code === "P2002") {
        return res
          .status(409)
          .json({ message: "Username already exists", error: "Conflict" });
      }
      return res
        .status(500)
        .json({ message: error, error: "Internal Server Error" });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
});

router.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: "Please provide all the required field",
      error: "Bad Request",
    });
  }

  await prisma.user
    .findUnique({
      where: {
        username,
      },
    })
    .then(async (user) => {
      if (!user) {
        return res.status(401).json({
          message: "Invalid Username or Password",
          error: "Unauthorized",
        });
      }

      const isValid = await bcrypt.compare(password, user.password);

      if (isValid) {
        const token = await new jose.SignJWT({
          username: user.username,
          email: user.email,
        })
          .setProtectedHeader({ alg: "HS256" })
          .setExpirationTime("1h")
          .sign(secret);

        return res.status(200).json({ message: "User logged in", token });
      } else {
        return res.status(401).json({
          message: "Invalid Username or Password",
          error: "Unauthorized",
        });
      }
    })
    .catch((error) => {
      return res
        .status(500)
        .json({ message: error, error: "Internal Server Error" });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
});

router.get("/me", verifyToken, async (req, res) => {
  const { username } = req.user;

  await prisma.user
    .findUnique({
      where: {
        username,
      },
    })
    .then((user) => {
      return res.status(200).json({ message: "Success", user });
    })
    .catch((error) => {
      return res
        .status(500)
        .json({ message: error, error: "Internal Server Error" });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
});

module.exports = router;
