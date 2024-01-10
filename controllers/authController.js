const User = require('../models/User');
const Token = require('../models/Token');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const { attachCookiesToResponse, createTokenUser,sendVerificationEmail,sendResetPasswordEmail, createHash } = require('../utils');
const crypto = require('crypto');
const { STATUS_CODES } = require('http');
// const sendEmail = require('../utils/sendEmail')

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');
  // const origin = 'http://localhost:3000'
  const origin = 'https://auth-front-end.onrender.com/'
  const user = await User.create({ name, email, password, role, verificationToken});

  await sendVerificationEmail({name:user.name, email:user.email,verificationToken:user.verificationToken, origin})
  const protocol = req.protocol
  const host = req.get('host')
  const forwardedHost = req.get('x-forwarded-host')
  const forwardedProtocol = req.get('x-forwarded-proto')
  const tempOrigin = req.get('origin')

  //send verification token back only when testing in Postman
  const tokenUser = createTokenUser(user);

  res.status(StatusCodes.CREATED).json({msg: "success, please check email to verify email", })
};

const verifyEmail = async(req,res) => {
  const {verificationToken, email} = req.body
  const user = await User.findOne({email})

  if(!user){
    throw new CustomError.UnauthenticatedError('Verification failed!')
  }

  if(user.verificationToken !== verificationToken){
    throw new CustomError.UnauthenticatedError('Verification failed')
  }

  user.isVerified = true
  user.verificationToken = ""
  user.verified = Date.now()
  await user.save()

  res.status(StatusCodes.OK).json({msg:"User successfully verified!"})
}

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if(!user.isVerified){
    throw new CustomError.UnauthenticatedError('User is not verified!');
  }
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const tokenUser = createTokenUser(user);

  //create refreshToken
  let refreshToken = ''
  // check for existing token
  const existingToken = await Token.findOne({user:user._id})

 if (existingToken) {
    const { isValid } = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    refreshToken = existingToken.refreshToken;
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });
    res.status(StatusCodes.OK).json({ user: tokenUser });
    return;
  }

  refreshToken = crypto.randomBytes(40).toString('hex')
  const userAgent = req.headers['user-agent']
  const ipAddress = req.ip
  const userToken = {refreshToken, userAgent, ipAddress, user:user._id}

  await Token.create(userToken)

  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUser });
};
const logout = async (req, res) => {
  await Token.findOneAndDelete({
    user: req.user.userId
  })
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const forgotPassword = async(req,res) => {
  const {email} = req.body
  if(!email){
    throw new CustomError.BadRequestError('Please provide valid email');
  }

  const user = await User.findOne({email})
  if(user){
    const passwordToken = crypto.randomBytes(70).toString('hex')
    // send email
    const origin = 'http://localhost:3000'
    await sendResetPasswordEmail({name:user.name,email:user.email, token:passwordToken, origin})
    const tenMinutes = 1000 * 60 *10
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)

    user.passwordToken = createHash(passwordToken)
    user.passwordTokenExpirationDate = passwordTokenExpirationDate

    await user.save();
  }
  res.status(StatusCodes.OK).json({msg:'Please check your email for reset password link'});
}

const resetPassword = async(req,res) => {
  const {token, email, password} = req.body
  if(!token || !email || !password){
    throw new CustomError.BadRequestError('Please provide all values')
  }

  const user = await User.findOne({email})

  if(user){
    const currentDate = new Date()

    // to check whether the reset password email has expired yet or not
    // once passed, then use the entered password to save as the new password for this user
    // put passwordToken and passwordTokenExpirationDate to null, so that any potential attacker cannot just use the reset password link forever to change the user's password
    // the user.passwordToken that was saved in the db cannot be unhashed anymore, so can only be compared against the token taken from frontend (after hashing it)
    if(user.passwordToken === createHash(token) && user.passwordTokenExpirationDate > currentDate){
      user.password = password
      user.passwordToken = ""
      user.passwordTokenExpirationDate = ""

      await user.save()
    }
  }
  res.send('reset password')
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword
};
