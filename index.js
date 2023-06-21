import express from 'express';
import Router from './Auth/Auth.js';
import cors from 'cors';
import database from './database.js';
import verifyToken from './middleware/authorise.js';
import dotenv from 'dotenv';
import User from './Model/User.js';
dotenv.config();
//Database Connection
database();
const app = express();
app.use(cors());
app.use(express.json());

app.get('/welcome', verifyToken, async (req, res) => {
  try {
    const { user_id } = req.user;
    const user = await User.findOne({ _id: user_id })
      .select('-password')
      .select('-token');
    res.json({ success: true, message: 'hello there', user: user });
  } catch (err) {
    res.status(400).json({ success: false, error: 'something is wrong' });
  }
});

app.use('/api/', Router);
app.listen(5555, () => console.log('server is running on port 5555'));
