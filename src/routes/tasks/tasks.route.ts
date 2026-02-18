// routes/task.routes.ts
import {
  addTask,
  deleteTask,
  getTask,
  getTasks,
  toggleTaskStatus,
  updateTask,
} from "@/controllers/tasks/tasks.controller";

import { requireAccessToken } from "@/middlewares/token.middleware";
import { Router } from "express";

export const taskRouter = Router();

// Apply Basic Auth to all task routes

taskRouter.post("/", requireAccessToken, addTask);
taskRouter.get("/", requireAccessToken, getTasks);
taskRouter.get("/:id", requireAccessToken, getTask);
taskRouter.put("/:id", requireAccessToken, updateTask);
taskRouter.delete("/:id", requireAccessToken, deleteTask);
taskRouter.patch("/:id/toggle", requireAccessToken, toggleTaskStatus);
