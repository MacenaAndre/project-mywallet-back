import express from 'express';
import cors from 'cors';
import { MongoClient } from "mongodb";
import joi from 'joi';
import bcrypt from "bcrypt"
import { v4 as uuid } from "uuid"
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const mongoClient = new MongoClient(process.env.MONGO_URI);

let db;

mongoClient.connect().then(() => {
	db = mongoClient.db("myWallet");
});

const registerSchema = joi.object({
    name: joi.string().required().empty(),
    email: joi.string().email().required(),
    password: joi.string().required().min(4),
    confirm_password: joi.ref("password")
});

const LogInSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required().min(4)
});

app.post("/register", async (req, res) => {
    const {name, email, password} = req.body;
    const validation = registerSchema.validate(req.body, {abortEarly: false});
    const passwordHash = bcrypt.hashSync(password, 12);

    if (validation.error) {
		return res.status(422).send({message: validation.error.details.map((value) => value.message).join(" & ")});
	};

    try {
		const users = await db.collection("users").find().toArray();
		const invalidEmail = users.find((value) => value.email === email);

		if(invalidEmail) {
			return res.status(409).send({message: "This email address is already beeing used"});
		};

        await db.collection("users").insertOne({
			name,
			email,
            passwordHash
		});

        return res.status(201).send({message: "User registered successfully"});

	} catch (error) {
		return res.status(500).send(error.message);
	}
});

app.post("/log-in", async (req, res) => {
    const {email, password} = req.body;
    const validation = LogInSchema.validate(req.body, {abortEarly: false});
    const token = uuid();
    
    if(validation.error) {
        return res.status(422).send({message: validation.error.details.map((value) => value.message).join(" & ")});
    };
    try {
        const user = await db.collection("users").findOne({email: email});
        const auth = await bcrypt.compare(password, user.passwordHash);

        if(user && auth) {
            db.collection("sessions").insertOne({
                userId: user._id,
                token
            });

            return res.status(200).send({
                name: user.name,
                email: user.email,
                token
            });

        } else {
            return res.status(401).send({message: "E-mail and/or password are invalid"});
        };

    } catch (error) {
		return res.status(500).send(error.message);

    }
    

});
app.listen(5000, () => console.log("Listening on port 5000..."));
