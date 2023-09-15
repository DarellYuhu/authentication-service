const bcrypt = require("bcryptjs");

async function passwordHash(password) {
  const salt = await bcrypt.genSalt();
  const hash = await bcrypt.hash(password, salt);

  return { hash, salt };
}

module.exports = passwordHash;
