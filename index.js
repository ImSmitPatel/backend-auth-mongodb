import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import db from "./utils/db.js";
import cookieParser from 'cookie-parser';

// import all routes
import userRoutes from "./routes/user.routes.js";


dotenv.config();
const app = express();
const port = process.env.PORT || 3000

app.use(
    cors({
        origin : process.env.BASE_URL,
        credentials: true,
        methods : ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization']
    })
);
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());


app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/smit', (req, res) => {
    res.send("Project by Smit Patel")
})

app.get('/cohort', (req, res) => {
    res.send("Cohort By Hitesh & Piyush")
})

//connect to db
db();

// user routes
app.use("/api/v1/users", userRoutes)



app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})