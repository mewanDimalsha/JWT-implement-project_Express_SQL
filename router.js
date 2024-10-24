const express = require("express");
const router = express.Router();
const controller = require("./controller");

router.post('/register', controller.registerUser);
router.post('/login', controller.loginUser);
router.get("/users", controller.getUsers);
router.get("/users/:id", controller.getUsersById);
router.post("/createuser", controller.addUser);

module.exports = router;
