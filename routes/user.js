const { PrismaClient } = require("@prisma/client");
const express = require("express");
const hashPassword = require("../utils/passwordHash");
const bcrypt = require("bcryptjs");
const router = express.Router();
const prisma = new PrismaClient();

router.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    res.json({ message: "Please provide all the required field" });
    return;
  }

  const { hash, salt } = await hashPassword(password);

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
      return res.json({ message: "User created" });
    })
    .catch((error) => {
      if (error.code === "P2002") {
        return res.json({ message: "Username already exists" });
      }
      return res.json({ message: error });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });

  // return res.sendStatus(500);
});

router.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.json({ message: "Please provide all the required field" });
    return;
  }

  await prisma.user
    .findUnique({
      where: {
        username,
      },
    })
    .then(async (user) => {
      if (!user) {
        return res.json({ message: "Invalid Username or Password" });
      }

      const isValid = await bcrypt.compare(password, user.password);

      if (isValid) {
        return res.json({ message: "User logged in", user });
      } else {
        return res.json({ message: "Invalid Username or Password" });
      }
    })
    .catch((error) => {
      return res.json({ message: error });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
});

module.exports = router;
