const jwt = require("jsonwebtoken");

const RefreshToken = require("../models/token");

const ACCESS_TOKEN_SECRET =
  "8cf692b814e5d06c5dffa1344d1419cc5f9b8dbaa2a08c724074362d20d54f1f72ff91c18eab18e372bc9a608526d532dfd099c5f1cc08d85bd1d13d5a032461";

const REFRESH_TOKEN_SECRET =
  "bb93964974dde6dfa1f5c9af4bc086903856b98d250ffd687a022b1719a107d37fb1f8a4162f4034623def0cd031c28a96e59391a2227e70a396cf405aa4e36f";

class JWTService {
  // sign access token
  static signAccessToken(payload, expiryTime) {
    return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: expiryTime });
  }

  // sign refresh token
  static signRefreshToken(payload, expiryTime) {
    return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: expiryTime });
  }

  // verify access token
  static verifyAccessToken(token) {
    return jwt.verify(token, ACCESS_TOKEN_SECRET);
  }

  // verify refresh token
  static verifyRefreshToken(token) {
    return jwt.verify(token, REFRESH_TOKEN_SECRET);
  }

  // store refresh token
  static async storeRefreshToken(token, userId) {
    try {
      const newToken = new RefreshToken({
        token: token,
        userId: userId,
      });

      // store in db
      await newToken.save();
    } catch (error) {
      console.log(error);
    }
  }
}

module.exports = JWTService;
