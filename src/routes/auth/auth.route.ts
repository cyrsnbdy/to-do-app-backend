// routes/auth/auth.route.ts
import {
  changePassword,
  forgotPassword,
  login,
  logout,
  register,
  verifyResetCode,
} from "@/controllers/auth/auth.controller";
import { Router } from "express";
export const authRouter = Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout); // Add basicAuth middleware here
authRouter.post("/forgot-password", forgotPassword);
authRouter.post("/verify-code", verifyResetCode);
authRouter.post("/change-password", changePassword);
