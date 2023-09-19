const express = require("express");
const userRoute = require("./routes/user");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.json({ message: "Welcome to authentication service" });
});

app.use("/user", userRoute);

app.listen(3010);
