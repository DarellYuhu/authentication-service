const bcrypt = require("bcryptjs");

async function passwordHash(password, res) {
  try {
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);

    return { hash, salt };
  } catch (error) {
    return res.status(500).json({ message: error });
  }
}

module.exports = passwordHash;
