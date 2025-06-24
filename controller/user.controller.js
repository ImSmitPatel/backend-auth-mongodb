import User from '../model/User.model.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const registerUser = async (req, res) => {

    // get data from user
    const { name, email, password } = req.body

    // validate data entere
    if (!name || !email || !password) {
        return res.status(400).json({
            status: "failed",
            message: "All fields are required"
        })
    }

    try {
        // check if user exists
        const existingUser = await User.findOne({ email: email })
        if (existingUser) {
            return res.status(400).json({
                status: "failed",
                message: "User already exists"
            })
        }

        // create a user in db
        const user = await User.create({
            name,
            email,
            password
        });

        if (!user) {
            return res.status(400).json({
                message: "User not registered",
            });
        }

         // create verification token
        const token = crypto.randomBytes(32).toString("hex")
        console.log("verification token: ", token);

        user.verificationToken = token;

        // save user to db
        await user.save()

        console.log("user: ", user);

        // email token to user
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });
        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: "Email Verification",
            text: `Please click on following link: ${process.env.BASE_URL}/api/v1/users/verify/${token}`,
        };

        await transporter.sendMail(mailOptions);

        // send success status to user
        res.status(201).json({
            message: "User registered successfully",
            success: true
        })

    } catch (error) {
        res.status(400).json({
            message: "User not registered",
            error,
            success: false
        })
    }
};

const verifyUser = async (req, res) => {
    // get toke from url params
    const {token} = req.params;

    // validate token
    if (!token) {
        return res.status(400).json({
            message: "Token not found",
            success: false
        })
    }

    // check if token exists in db
    const user = await User.findOne({verificationToken: token});
    
    if (!user) {
        return res.status(400).json({
            message: "Invalid token",
            success: false
        })
    }

    // if token exists, update isVerified to true
    user.isVerified = true;

    // remove token from db
    user.verificationToken = undefined

    // save user
    await user.save()

    // return response
    res.status(200).json({
        message: "User verified successfully",
        success: true
    });
};

const login = async (req, res) => {
    // get data from user
    const {email, password} = req.body;

    // validate data entered
    if (!email || !password) {
        return res.status(400).json({
            message: "All fields are required",
            success: false
        })
    }

    // check if user exists
    try {
        const user = await User.findOne({email})
        if(!user) {
            return res.status(400).json({
                message: "Invalid Credentials",
                success: false
            });
        }
        

        // check if password is correct
        const isMatch = await bcrypt.compare(password, user.password)

        console.log("password matched: ", isMatch);
        if (!isMatch){
            return res.status(400).json({
                message: "Invalid Credentials",
                success: false
            });
        }

        // check if user is verified
        if(!user.isVerified){
            res.status(400).json({
                success: false,
                message: "Please verify emai before login"
            })
        }

        // generate jwt token
        const token = jwt.sign(
            {
                id: user._id, 
                role: user.role
            }, 
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION_TIME }
        );
        
        // save token in cookies
        const cookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24*60*60*1000
        };

        res.cookie("token", token, cookieOptions);
        
        // SEND RESPONSE TO USER
        res.status(200).json({
            success: true,
            message: "Login Successful",
            token,
            user: {
                id: user._id,
                name: user.name,
                role: user.role,
            }
        });

    } catch (error) {

        console.log("error: ", error);


        return res.status(400).json({
            message: "User wasn't logged in final",
            success: false,
        });
    } 
};

const logout = async (req, res) => {
    try {
        res.cookie('token', '', {});
        res.status(200).json({
            success: true,
            message: "logged out successfully"
        })
    } catch (error) {
        
    }
};

const getProfile = async (req, res) => {
    try {
        const data = req.user
        console.log("Reached at profile level", data);

        const user = await User.findById(req.user.id).select('-password')

        if(!user) {
            return res.status(400).json({
                success : false,
                message: "User not found"
            })
        }

        return res.status(200).json({
            success: true,
            message: "User Found",
            email: user.email,
            name: user.name,
            role: user.role
        })

    } catch (error) {
        console.log("error in getProfile controller: ", error);
        return res.status(500).json({
            success: false,
            message: "Internal server Error"
        })
    }
};

const forgotPassword = async (req, res) => {
    const {email} = req.body;

    if(!email) {
        return res.status(400).json({
            success: false,
            message: "Email is required"
        })
    }

    try {

        const user = await User.findOne({email});
    
        if(!user) {
            console.log("forgotPassword controller: User not found");
            return res.status(400).json({
                success: false,
                message: "User not found"
            })
        }
    
        // generate token
        const token = crypto.randomBytes(32).toString("hex");
        console.log(token);
    
        // save token in db
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 10*60*1000;
    
        await user.save();
    
        console.log("user: ", user);

        // email token to user
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });
        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: "Email Verification",
            text: `Please click on following link: ${process.env.BASE_URL}/api/v1/users/reset-password/${token}`,
        };

        await transporter.sendMail(mailOptions);
        
        return res.status(200).json({
            status: true,
            message: "Email sent successfully"
        })

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        })
    }
};

const resetPassword = async (req, res) => {
    // collect token from params
    // get password from req.body
    const {token} = req.params
    const {password, confirmPassword} = req.body

    if(!password || !confirmPassword) {
        return res.status(400).json({
            success: false,
            message: "All fields are required"
        })
    }

    if(password !== confirmPassword) {
        return res.status(400).json({
            success: false,
            message: "Passwords do not match"
        });
    }


    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: {$gt : Date.now()}
        })

        if(!user) {
            res.status(400).json({
                success: false,
                message: "Token is invalid or has expired"
            })
        }

        console.log("old user: ", user);

        // set password in user
        user.password = password;

        // resetToken, resetExpiry => reset
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        
        console.log("new user: ", user);
        // save user
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully"
        })

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        })
    }
};

export { registerUser, verifyUser, login, logout, getProfile, forgotPassword, resetPassword }