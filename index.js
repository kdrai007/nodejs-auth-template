import express from 'express';
import Router from './Auth/Auth.js';
import cors from 'cors';
import database from './database.js';
import verifyToken from './middleware/authorise.js';
import dotenv from 'dotenv';
dotenv.config();
//Database Connection
database();
const app = express();
app.use(cors());
app.use(express.json());

app.get('/welcome', verifyToken, (req, res) => {
  console.log(req.user);
  res.json({ message: 'hello there' });
});

app.use('/api/', Router);
app.listen(5555, () => console.log('server is running on port 5555'));
