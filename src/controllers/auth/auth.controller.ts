import { compareHashed, hashValue } from "@/utils/bcrypt/bcrypt.util";
import { sendResetCodeEmail } from "@/utils/mail/mail.util";
import crypto from "crypto";
import { Request, Response } from "express";
// libraries

import { v4 as uuid } from "uuid";
// Models
// Services
import {
  findAccountS,
  pushSessionS,
  registerS,
} from "@/services/account/account.service";
// Utils
import Account from "@/models/account/account.model";
import {
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
  setRefreshCookie,
} from "@/utils/cookie/cookie.util";
import { AppError } from "@/utils/error/app-error.util";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "@/utils/jwt/jwt.util";
import { buildSession } from "@/utils/session/session.util";

/**
 * @description Register a new user account
 * @route POST /api/auth/register
 * @access Public
 */
export const register = async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  // Validate that all required fields are provided
  if (!name || !email || !password)
    throw new AppError("All fields are required.", 400);

  // Check if an account with the same email already exists
  if (await findAccountS({ email })) {
    throw new AppError("Email already exists.", 409);
  }

  // Hash the user's password before storing in database
  const hashedPassword = await hashValue(password);

  // Create and store the new account in the database
  const account = await registerS({
    name,
    email,
    password: await hashValue(password),
  });
  if (!account) throw new AppError("Failed to create account.", 500);

  // Get uuid
  const sid = uuid();

  // Generate tokens
  const sub = String(account._id);
  const accessToken = signAccessToken(sub);
  const refreshToken = signRefreshToken(sub, sid);

  // Build session and save it in database
  const session = await buildSession(req, refreshToken, sid);

  // Push the session to database
  const updated = await pushSessionS(String(account._id), session);
  if (!updated) throw new AppError("Account not found.", 404);

  // Set the refresh token in cookie
  setRefreshCookie(res, refreshToken);

  // Send response
  return res.status(200).json({
    message: "Account registered successfully.",
    accessToken,
  });
};

/**
 * @description Authenticate a user and log them in
 * @route POST /api/auth/login
 * @access Public
 */
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // Validate that both email and password are provided
  if (!email || !password) {
    throw new AppError("Fill all contents. Email/Password", 400);
  }

  // Find the account using the provided email
  const account = await findAccountS({ email });

  // Throw error if account does not exist
  if (!account) {
    throw new AppError("Account not found", 400);
  }

  // Compare provided password with the stored hashed password
  const passwordCheck = await compareHashed(password, account.password);
  if (!passwordCheck) {
    throw new AppError("Incorrect Password.", 400);
  }

  const sid = uuid();

  // Generate tokens
  const sub = String(account._id);
  const accessToken = signAccessToken(sub);
  const refreshToken = signRefreshToken(sub, sid);

  // Build session and save it in database
  const session = await buildSession(req, refreshToken, sid);

  // Push the session to database
  const updated = await pushSessionS(String(account._id), session);
  if (!updated) throw new AppError("Account not found.", 404);

  // Set the refresh token in cookie
  setRefreshCookie(res, refreshToken);

  // Send response
  return res.status(200).json({
    message: "Login successfully.",
    accessToken,
  });
};

/**
 * @description Log out a user by updating their account status
 * @route POST /api/auth/logout
 * @access Public
 */
// controllers/auth/auth.controller.ts
export const logout = async (req: Request, res: Response) => {
  // Get the refresh token from cookie
  const token = req.cookies?.[REFRESH_COOKIE_NAME];

  // Revoke the refresh token by removing the session from database
  if (token) {
    try {
      const payload = verifyRefreshToken(token) as { sub: string; sid: string };

      // revoke ONLY this session (preferred)
      await Account.updateOne(
        { _id: payload.sub },
        { $pull: { sessions: { sid: payload.sid } } },
      );
    } catch (err) {
      // log only in development
      if (process.env.NODE_ENV !== "production")
        console.error("Logout verify failed:", err);
    }
  }

  // Clear the refresh token cookie
  clearRefreshCookie(res);

  // Send response
  return res.status(200).json({ message: "Logged out successfully." });
};

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    throw new AppError("Email is required.", 400);
  }

  const account = await findAccountS({ email });

  // Prevent email enumeration
  if (!account) {
    return res.status(200).json({
      message: "If an account exists, a reset code was sent.",
    });
  }

  const code = crypto.randomInt(100000, 999999).toString();
  const hashedCode = await hashValue(code);

  await Account.updateOne(
    { _id: account._id },
    {
      passwordResetCode: hashedCode,
      passwordResetExpires: new Date(Date.now() + 10 * 60 * 1000),
    },
  );

  await sendResetCodeEmail(account.email, code);

  return res.status(200).json({
    message: "If an account exists, a reset code was sent.",
  });
};

export const resetPassword = async (req: Request, res: Response) => {
  const { email, code, password } = req.body;

  if (!email || !code || !password) {
    throw new AppError("All fields are required.", 400);
  }

  const account = await findAccountS({ email });

  if (!account || !account.passwordResetCode || !account.passwordResetExpires) {
    throw new AppError("Invalid or expired reset request.", 400);
  }

  if (account.passwordResetExpires < new Date()) {
    throw new AppError("Reset code expired.", 400);
  }

  const isMatch = await compareHashed(code, account.passwordResetCode);

  if (!isMatch) {
    throw new AppError("Invalid reset code.", 400);
  }

  const newHashedPassword = await hashValue(password);

  await Account.updateOne(
    { _id: account._id },
    {
      password: newHashedPassword,
      passwordResetCode: undefined,
      passwordResetExpires: undefined,
      sessions: [], // revoke all sessions
    },
  );

  return res.status(200).json({
    message: "Password reset successfully.",
  });
};
