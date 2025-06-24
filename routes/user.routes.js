import express from 'express'
import { forgotPassword, getProfile, login, logout, registerUser, resetPassword, verifyUser } from '../controller/user.controller.js'
import { isLoggedIn } from '../middleware/auth.middleware.js';

const router = express.Router();

// register user
router.post("/register", registerUser);

// verify email
router.get("/verify/:token", verifyUser);

// login user
router.post("/login", login);

// getProfile
router.get("/profile", isLoggedIn, getProfile);

// logout
router.get("/logout", isLoggedIn, logout)

// forgot pass
router.post("/forgot-password", forgotPassword);

// reset pass
router.post("/reset-password/:token", resetPassword);


export default router;