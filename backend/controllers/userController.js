const User = require('../models/userModel.js')
const catchAsyncErrors = require('../middlewares/catchAsyncError.js');
const sendToken = require('../utils/jwtToken.js');
const sendEmail=require('../utils/sendEmail.js')
const crypto=require('crypto')


exports.registerUser = catchAsyncErrors(async (req, res, next) => {
    const { name, email, password } = req.body;

    if (req.body.password!==req.body.confirmPassword) {
        res.status(400).json({
            success: false,
            message: "Passwords do not match"
        })
    }

    const user = await User.create({
        name, email, password
    })

    sendToken(user, 201, res);
})


exports.loginUser = catchAsyncErrors(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(400).json({
            success: false,
            message: "Enter email and password both"
        })
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
        res.status(401).json({
            success: false,
            message: "User not found"
        })
    }

    const isPasswordMatched = await user.comparePassword(password);

    if (!isPasswordMatched) {
        res.status(401).json({
            success: false,
            message: "Email or Password incorrect"
        })
    }

    sendToken(user, 200, res);
})


exports.logout = catchAsyncErrors(async (req, res, next) => {
    res.cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
    });

    res.status(200).json({
        success: true,
        message: "Logged out Successfully"
    })
})


exports.forgotPassword = catchAsyncErrors(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        res.status(404).json({
            success: false,
            message: "User not found"
        })
    }

    const resetToken = user.getResetPasswordToken();

    await user.save({ validateBeforeSave: false });

    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/password/reset/${resetToken}`

    const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\n If you have not requested this mail, then please ignore it`

    try {

        await sendEmail({
            email:user.email,
            subject:`HRApp Password reset`,
            message
        });
        res.status(200).json({
            success: true,
            message: `Email sent to ${user.email} successfully`,
        })
        
    } catch (error) {
        user.resetPasswordToken=undefined;
        user.resetPasswordExpire=undefined;

        await user.save({ validateBeforeSave: false });

        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
})


exports.resetPassword = catchAsyncErrors(async (req, res, next)=>{
    const resetPasswordToken=crypto.createHash("sha256").update(req.params.token).digest("hex");

    const user=await User.findOne({
        resetPasswordToken,
        resetPasswordExpire:{$gt:Date.now()}
    })

    if (!user) {
        res.status(400).json({
            success: false,
            message: "Reset Password Token is Invalid or expired"
        })
    }

    if (req.body.password!==req.body.confirmPassword) {
        res.status(400).json({
            success: false,
            message: "Passwords do not match"
        })
    }

    user.password=req.body.password;
    user.resetPasswordToken=undefined;
    user.resetPasswordExpire=undefined;

    await user.save();

    sendToken(user, 200, res);
})


exports.updatePassword=catchAsyncErrors(async(req,res,next)=>{
    const user=await User.findById(req.user.id).select("+password");

    const isPasswordMatched = await user.comparePassword(req.body.oldPassword);

    if (!isPasswordMatched) {
        res.status(400).json({
            success: false,
            message: "Old Password incorrect"
        })
    }

    if (req.body.newPassword!==req.body.confirmPassword) {
        res.status(400).json({
            success: false,
            message: "Passwords do not match"
        })
    }

    user.password=req.body.newPassword;

    await user.save();

    sendToken(user, 200, res);
})


exports.getUserDetails=catchAsyncErrors(async(req,res,next)=>{
    const user=await User.findById(req.user.id);

    if (!user) {
        res.status(401).json({
            success: false,
            message: "User not found"
        })
    }

    res.status(200).json({
        success: true,
        user
    })

})


exports.updateProfile=catchAsyncErrors(async(req,res,next)=>{
    const newUserData={
        name:req.body.name,
        email:req.body.email
    };

    const user=await User.findByIdAndUpdate(req.user.id,newUserData,{
        new:true,
        runValidators:true,
        useFindAndModify:false
    });

    res.status(200).json({
        success: true,
    })
})
