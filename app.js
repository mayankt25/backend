import { connect, Schema, model } from "mongoose";
import express, { json } from "express";
import cors from "cors";
import { urlencoded } from "body-parser";
import { body, validationResult } from "express-validator";
import { hash as _hash, compare } from "bcrypt";
import { sign } from "jsonwebtoken";
import fetchUser from "./middleware/fetchuser";
const saltRounds = 10;
const app = express();

const url = process.env.DATABASE_URL;

const PORT = process.env.PORT || 3000;
connect(url);

app.use(urlencoded({ extended: true }));
app.use(json());
app.use(cors());

const userSchema = new Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const noteSchema = new Schema({
    user: {
        type: Schema.Types.ObjectId,
        ref: "User"
    },
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const User = model("User", userSchema);
const Note = model("Note", noteSchema);
User.createIndexes();

app.get("/", function (req, res) {
    res.send("Hello");
});

app.post("/api/auth/createuser", [
    body("name", "Please enter a valid name with atleast three characters").isLength({ min: 3 }),
    body("email", "Please enter a valid email").isEmail(),
    body("password", "Password must be atleast six characters").isLength({ min: 6 })
], async function (req, res) {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success, error: errors.array() });
    }

    const checkForDuplication = await User.findOne({ email: req.body.email });

    try {
        if (checkForDuplication) {
            res.json({ success, error: "User already exists" });
        }
    } catch (error) {
        console.log(error);
    }

    if(!checkForDuplication){
        try {
            _hash(req.body.password, saltRounds, function (err, hash) {
                const user = new User({
                    name: req.body.name,
                    email: req.body.email,
                    password: hash
                });
                user.save().then((user) => {
                    const data = {
                        user: {
                            _id: user._id
                        }
                    }
                    const authToken = sign(data, process.env.JWT_SECRET);
                    success = true;
                    res.json({ success, authToken });
                }).catch(err => {
                    console.log(err);
                    success = false;
                    res.json({ success, error: "Internal Server Error" });
                });
            });
        } catch (error) {
            res.json({success, error});
        }
    }
});

app.post("/api/auth/login", [
    body("email", "Please enter a valid email.").isEmail(),
    body("password", "Password must not be blank.").exists()
], function (req, res) {
    let success = false;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success, errors: errors.array() });
    }
    const email = req.body.email;
    const password = req.body.password;
    User.findOne({ email: email }).then(function (foundUser) {
        if (!foundUser) {
            return res.status(404).json({ success, error: "Please enter correct login credentials." });
        }
        compare(password, foundUser.password, function (err, result) {
            if (result === true) {
                const data = {
                    user: {
                        _id: foundUser._id
                    }
                }
                const authToken = sign(data, process.env.JWT_SECRET);
                success = true;
                res.json({ success, authToken });
            } else {
                return res.status(404).json({ success, error: "Please enter correct login credentials." });
            }
        });
    });
});

app.post("/api/auth/getuser", fetchUser, async function (req, res) {
    try {
        user = req.user._id;
        const user = await User.findById(user).select("-password");
        res.send(user);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

// For Notes

app.get("/api/notes/fetchallnotes", fetchUser, async (req, res) => {
    try {
        const notes = await Note.find({ user: req.user._id });
        res.json(notes);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/api/notes/addnote", fetchUser, [
    body("title", "Please enter a valid title with atleast three characters.").isLength({ min: 5 }),
    body("description", "Please enter a valid description with atleast seven characters.").isLength({ min: 7 }),
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const newNote = new Note({
            user: req.user._id,
            title: req.body.title,
            description: req.body.description
        });

        newNote.save();
        res.json(newNote);

    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.put("/api/notes/updatenote/:id", fetchUser, async (req, res) => {
    try {
        const { title, description } = req.body;
        const newNote = {};
        if (title) {
            newNote.title = title;
        }
        if (description) {
            newNote.description = description;
        }
        let foundNote = await Note.findById(req.params.id);
        if (!foundNote) {
            return res.status(404).send("Not Found.");
        }
        if (foundNote.user.toString() !== req.user._id) {
            return res.status(401).send("Action not allowed.");
        }
        foundNote = await Note.findByIdAndUpdate(req.params.id, { $set: newNote }, { new: true });
        res.send(foundNote);
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.delete("/api/notes/deletenote/:id", fetchUser, async (req, res) => {
    try {
        let foundNote = await Note.findById(req.params.id);
        if (!foundNote) {
            return res.status(404).send("Not Found.");
        }
        if (foundNote.user.toString() !== req.user._id) {
            return res.status(401).send("Action not allowed.");
        }
        foundNote = await Note.findByIdAndDelete(req.params.id);
        res.json({ Success: "Note deleted successfully." });
    } catch (error) {
        console.log(error.message);
        res.status(500).send("Internal Server Error");
    }
});

app.listen(PORT, () => {
    console.log("Listening on port 3000");
});