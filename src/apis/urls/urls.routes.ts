import express from "express";
import { shorten, redirect, deleteUrl } from "./urls.controllers";
import { auth } from "../../middlewares/auth";

const router = express.Router();


router.post("/shorten", auth, shorten);


router.get("/:code", redirect);


router.delete("/:code", auth, deleteUrl);

export default router;
