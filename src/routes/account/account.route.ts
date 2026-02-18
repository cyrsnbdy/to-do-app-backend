import { getAccount } from "@/controllers/account/account.controller";
import { requireAccessToken } from "@/middlewares/token.middleware";
import { Router } from "express";

export const accountRouter = Router();

accountRouter.get("/", requireAccessToken, getAccount);
