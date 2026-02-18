// routes/auth/auth.route.ts
import { login, logout, register } from "@/controllers/auth/auth.controller";
import { Router } from "express";
import {
  forgotPassword,
  resetPassword,
} from "@/controllers/auth/auth.controller";
export const authRouter = Router();

authRouter.post("/register", register);
authRouter.post("/login", login);
authRouter.post("/logout", logout); // Add basicAuth middleware here
authRouter.post("/forgot-password", forgotPassword);
authRouter.post("/reset-password", resetPassword);
