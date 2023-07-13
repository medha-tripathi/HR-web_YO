const catchAsyncErrors=require('./catchAsyncError.js')
const jwt=require('jsonwebtoken')
const User = require('../models/userModel.js')

exports.isAuthenciatedUser=catchAsyncErrors(async(req,res,next)=>{
    const {token}=req.cookies;

    if (!token) {
        res.status(401).json({
            success: false,
            message: "Please Login to access this resource"
        })
    }

    const decodedData=jwt.verify(token,process.env.JWT_SECRET);     //Provide any string as JWT Secret

    req.user=await User.findById(decodedData.id);
    next();
}) 