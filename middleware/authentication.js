const CustomError = require('../errors');
const { isTokenValid } = require('../utils');
const Token = require('../models/Token')
const { attachCookiesToResponse } = require('../utils');

const authenticateUser = async (req, res, next) => {
  // const token = req.signedCookies.token;
  const {refreshToken, accessToken} = req.signedCookies
  console.log(req.signedCookies)
  try {
    if(accessToken){
      const payload = isTokenValid(accessToken)
      req.user = payload.user
      return next()
    }

    //if access token does not exist
    const payload = isTokenValid(refreshToken)

    const existingToken = await Token.findOne({
      user:payload.user.userId,
      refreshToken: payload.refreshToken
    })
    console.log('weweqe')
    console.log(payload)

    if(!existingToken || !existingToken?.isValid){
      console.log('something is wrong')
      throw new CustomError.UnauthenticatedError('Authentication Invalid')
    }
    attachCookiesToResponse({
      res,
      user:payload.user,
      refreshToken:existingToken.refreshToken
    })
    console.log('we are here!')
  } catch (error) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new CustomError.UnauthorizedError(
        'Unauthorized to access this route'
      );
    }
    next();
  };
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};
