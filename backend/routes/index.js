const express = require("express");

const authController = require("../controller/authController");

const blogController = require("../controller/blogController");

const commentController = require("../controller/commentController");

const auth = require("../middlewares/auth");
const router = express.Router();

//test
router.get("/test", (req, res) => {
  res.json({ msg: "hello" });
});

//register
router.post("/register", authController.register);

//login
router.post("/login", authController.login);

router.post("/logout", auth, authController.logout);
router.get("/refresh", authController.refresh);

///////-------blog

//create
router.post("/blog", auth, blogController.create);
//get all
router.get("/blog/all", auth, blogController.getAll);
//get blog by id
router.get("/blog/:id", auth, blogController.getById);
//update
router.put("/blog", auth, blogController.update);
//delete
router.delete("/blog/:id", auth, blogController.delete);

//////-----comment
// create
router.post("/comment", auth, commentController.create);

// get
router.get("/comment/:id", auth, commentController.getById);
module.exports = router;
