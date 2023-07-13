const express=require('express');
const { registerUser, loginUser, logout, forgotPassword, resetPassword, getUserDetails, updatePassword, updateProfile } = require('../controllers/userController.js');
const { isAuthenciatedUser } = require('../middlewares/auth.js');


const router=express.Router();

router.post("/register",registerUser);
router.post("/login",loginUser);
router.get("/logout",isAuthenciatedUser,logout);
router.post("/password/forgot",forgotPassword);
router.put("/password/reset/:token",resetPassword);
router.put("/password/update",isAuthenciatedUser,updatePassword);
router.get("/me",isAuthenciatedUser,getUserDetails);
router.put("/me/update",isAuthenciatedUser,updateProfile);

module.exports=router;