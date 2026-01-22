import { NextFunction, Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../../models/User";

const SALT = 10;

// SIGN UP
export const signup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, password } = req.body as { username?: string; password?: string };

        if (typeof username !== "string" || typeof password !== "string") {
            res.status(400).json({ error: "Username and password are required" });
            return;
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            res.status(400).json({ error: "Username already exists" });
            return;
        }

        const hashedPassword = await bcrypt.hash(password, SALT);

        const newUser = await User.create({
            username,
            password: hashedPassword,
        });

        const token = jwt.sign(
            { _id: newUser._id, username: newUser.username },
            process.env.JWT_SECRET as string,
            { expiresIn: "7d" }
        );

        res.status(201).json({ token });
        return;
    } catch (err) {
        next(err);
    }
};

// SIGN IN
export const signin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, password } = req.body as { username?: string; password?: string };

        if (typeof username !== "string" || typeof password !== "string") {
            res.status(400).json({ error: "Username and password are required" });
            return;
        }

        const user = await User.findOne({ username }).select("+password");
        if (!user) {
            res.status(401).json({ error: "Invalid credentials" });
            return;
        }

        if (typeof user.password !== "string") {
            res.status(500).json({ error: "Password is missing on user record" });
            return;
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            res.status(401).json({ error: "Invalid credentials" });
            return;
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET as string,
            { expiresIn: "7d" }
        );

        res.status(200).json({
            token,
            user: {
                id: user._id,
                username: user.username,
            },
        });
        return;
    } catch (err) {
        next(err);
    }
};

// GET USERS
export const getUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const users = await User.find().populate("urls");
        res.status(200).json(users);
        return;
    } catch (err) {
        next(err);
    }
};
