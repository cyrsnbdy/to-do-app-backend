import { AuthedRequest } from "@/middlewares/token.middleware";
import { Response } from "express";

export const getAccount = async (req: AuthedRequest, res: Response) => {
  const account = req.account;
  res.status(200).json({ account });
};
