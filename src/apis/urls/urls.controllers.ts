import Url from "../../models/Url";
import shortid from "shortid";
import User from "../../models/User";
import { NextFunction, Request, Response } from "express";
import { AuthRequest } from "../../middlewares/auth";

const baseUrl = "http://localhost:8000/urls";

// ✅ Create Short URL (Protected)
export const shorten = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const urlCode = shortid.generate();

    try {
        // userId من التوكن (مو من params)
        const userId = req.user?.userId || req.user?._id;

        if (!userId) {
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        req.body.shortUrl = `${baseUrl}/${urlCode}`;
        req.body.urlCode = urlCode;
        req.body.userId = userId;

        const newUrl = await Url.create(req.body);

        await User.findByIdAndUpdate(userId, {
            $push: { urls: newUrl._id },
        });

        res.status(201).json(newUrl);
        return;
    } catch (err) {
        next(err);
    }
};

// ✅ Redirect (Public)
export const redirect = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const url = await Url.findOne({ urlCode: req.params.code });

        if (!url) {
            res.status(404).json("No URL Found");
            return;
        }

        res.redirect(url.longUrl || "");
        return;
    } catch (err) {
        next(err);
    }
};

// ✅ Delete URL (Protected + Ownership)
export const deleteUrl = async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
        // userId من التوكن
        const userId = req.user?.userId || req.user?._id;

        if (!userId) {
            res.status(401).json({ error: "Unauthorized" });
            return;
        }

        const url = await Url.findOne({ urlCode: req.params.code });

        if (!url) {
            res.status(404).json("No URL Found");
            return;
        }

        // ✅ حل مشكلة TS + تأكيد وجود المالك
        if (!url.userId) {
            res.status(500).json({ error: "URL owner is missing" });
            return;
        }

        // ✅ تحقق الملكية: ما يقدر يحذف إلا صاحب الرابط
        if (url.userId.toString() !== userId.toString()) {
            res.status(403).json({ error: "Forbidden" });
            return;
        }

        await Url.findByIdAndDelete(url._id);

        res.status(200).json("Deleted");
        return;
    } catch (err) {
        next(err);
    }
};
