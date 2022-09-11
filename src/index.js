import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from "mongodb";
import joi from 'joi';
import bcrypt from "bcrypt"
import { v4 as uuid } from "uuid"
import dayjs from 'dayjs';
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

const entrySchema = joi.object({
    value: joi.number().precision(2).required(),
    description: joi.string().required().empty(),
    isIncome: joi.boolean().required()
});

app.post("/register", async (req, res) => {
    const {name, email, password} = req.body;
    const validation = registerSchema.validate(req.body, {abortEarly: false});

    if (validation.error) {
        return res.status(422).send({message: validation.error.details.map((value) => value.message).join(" & ")});
    };

    if(!req.body.confirm_password) {
        return res.status(422).send({message: "Please confirm your password"});
    };

    try {
        const passwordHash = bcrypt.hashSync(password, 12);
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

app.post("/session", async (req, res) => {
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
                token,
                logstatus: Date.now()
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

app.delete("/session", async (req, res) => {
    const {authorization} = req.headers;
    const token = authorization?.replace('Bearer ', '');

    if(!token) return res.status(401).send({message: "headers is required with the following format {Authorization: Bearer 'token'}"});

    try {
        const validSession = await db.collection("sessions").findOne({token: token});

        if(!validSession) {
            return res.status(401).send({message: "Invalid token"})
        };

        await db.collection("sessions").deleteOne({token: token});
        return res.status(200).send("User logged out");

    } catch (error) {
        return res.status(500).send(error.message);
    }
});

app.get("/data", async (req, res) => {
    const {authorization} = req.headers;
    const token = authorization?.replace('Bearer ', '');

    if(!token) return res.status(401).send({message: "headers is required with the following format {Authorization: Bearer 'token'}"});

    try {
        const validSession = await db.collection("sessions").findOne({token: token});

        if(!validSession) {
            return res.status(401).send({message: "Invalid token"})
        };

        const userHistory = await db.collection("data").find({userId: validSession.userId}).toArray();
        res.status(200).send(userHistory);

    } catch (error) {
        return res.status(500).send(error.message);
    };
});

app.post("/data", async (req, res) => {
    const {authorization} = req.headers;
    const {value, description, isIncome} = req.body;
    const validation = entrySchema.validate(req.body, {abortEarly: false, convert: false});
    const token = authorization?.replace("Bearer ", "");

    if(!token) return res.status(401).send({message: "headers is required with the following format {Authorization: Bearer token}"});

    if(validation.error) {
        return res.status(422).send({message: validation.error.details.map((value) => value.message).join(" & ")});
    };
        
    try {
        const validSession = await db.collection("sessions").findOne({token: token});

        if(!validSession) return res.status(401).send({message: "Invalid token"});

        await db.collection("data").insertOne({
            value,
            description,
            isIncome,
            userId: validSession.userId,
            date: dayjs().format("DD/MM")
        });

        return res.status(201).send({message: "Entry posted successfully"});

    } catch (error) {
        return res.status(500).send(error.message);
    };
});

app.delete("/data/:idEntry", async (req, res) => {
    const {authorization} = req.headers;
    const {idEntry} = req.params;
    const token = authorization?.replace('Bearer ', '');

    if(!token) return res.status(401).send({message: "headers is required with the following format {Authorization: Bearer 'token'}"});

    try {
        const entry = await db.collection("data").findOne({_id: new ObjectId(idEntry)});

        if(!entry) return res.status(404).send({message: "id invalid"});

        await db.collection("data").deleteOne({_id: new ObjectId(idEntry)});

        return res.status(200).send("Entry deleted");

    } catch (error) {
        return res.status(500).send(error.message);
    }
});

app.listen(5000, () => console.log("Listening on port 5000..."));
