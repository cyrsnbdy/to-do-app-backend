import { compareHashed, hashValue } from "@/utils/bcrypt/bcrypt.util";
import { sendResetCodeEmail } from "@/utils/mail/mail.util";
import crypto from "crypto";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
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
    name,
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
  const name = account?.name;

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
    user: {
      id: account._id,
      name: account.name,
      email: account.email,
    },
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
      passwordResetAttempts: 0,
    },
  );

  // Fire and forget
  sendResetCodeEmail(account.email, code).catch((err) => {
    console.error("Reset email error:", err);
  });

  return res.status(200).json({
    message: "If an account exists, a reset code was sent.",
  });
};

export const verifyResetCode = async (req: Request, res: Response) => {
  const { email, code } = req.body;

  if (!email || !code) {
    throw new AppError("Email and code are required.", 400);
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
    await Account.updateOne(
      { _id: account._id },
      { $inc: { passwordResetAttempts: 1 } },
    );

    throw new AppError("Invalid reset code.", 400);
  }

  // Create short-lived reset token (5–10 minutes)
  const resetToken = jwt.sign(
    { sub: account._id },
    process.env.JWT_RESET_SECRET as string,
    { expiresIn: "10m" },
  );

  return res.status(200).json({
    message: "Code verified successfully.",
    resetToken,
  });
};

export const changePassword = async (req: Request, res: Response) => {
  const { resetToken, newPassword } = req.body;
  console.log(req.body);

  console.log("RESET SECRET:", process.env.JWT_RESET_SECRET);
  console.log("TOKEN:", resetToken);

  if (!resetToken || !newPassword) {
    throw new AppError("Reset token and new password are required.", 400);
  }

  let payload: any;

  try {
    payload = jwt.verify(resetToken, process.env.JWT_RESET_SECRET as string);
  } catch (err) {
    throw new AppError("Invalid or expired reset token.", 400);
  }

  const account = await Account.findById(payload.sub);

  if (!account) {
    throw new AppError("Account not found.", 404);
  }

  const newHashedPassword = await hashValue(newPassword);

  await Account.updateOne(
    { _id: account._id },
    {
      password: newHashedPassword,
      passwordResetCode: undefined,
      passwordResetExpires: undefined,
      passwordResetAttempts: 0,
      sessions: [], // revoke all sessions
    },
  );

  return res.status(200).json({
    message: "Password changed successfully.",
  });
};
