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
        const payload = {
          username: user.username,
          email: user.email,
        };

        const accessToken = await new jose.SignJWT(payload)
          .setProtectedHeader({ alg: "HS256" })
          .setExpirationTime("20s")
          .sign(secret);

        const refreshToken = await new jose.SignJWT(payload)
          .setProtectedHeader({ alg: "HS256" })
          .sign(secret);

        await prisma.refreshToken.create({
          data: {
            token: refreshToken,
            userId: user.id,
          },
        });

        return res
          .status(200)
          .json({ message: "User logged in", accessToken, refreshToken });
      } else {
        return res.status(401).json({
          message: "Invalid Username or Password",
          error: "Unauthorized",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      return res
        .status(500)
        .json({ message: error, error: "Internal Server Error" });
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
});

router.delete("/signout", async (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Unathorized",
      error: "Unauthorized",
    });
  }

  try {
    await prisma.refreshToken.delete({
      where: {
        token: refreshToken,
      },
    });

    return res.sendStatus(204);
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({
        message: "Token not found",
        error: "Not Found",
      });
    }
    return res.status(500).json({
      message: error,
      error: "Internal Server Error",
    });
  }
});

router.post("/refresh-token", async (req, res) => {
  const refreshToken = req.body.token;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Unathorized",
      error: "Unauthorized",
    });
  }

  try {
    const isValid = await prisma.refreshToken.findFirst({
      where: {
        token: refreshToken,
      },
    });

    if (!isValid) {
      return res.status(401).json({
        message: "Unathorized",
        error: "Unauthorized",
      });
    }

    const { payload } = await jose.jwtVerify(refreshToken, secret);

    const accessToken = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("20s")
      .sign(secret);

    return res.status(200).json({ message: "Success", accessToken });
  } catch (error) {
    return res.status(500).json({
      message: error,
      error: "Internal Server Error",
    });
  }
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
