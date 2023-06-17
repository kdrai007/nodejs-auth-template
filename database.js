import mongoose from 'mongoose';
mongoose.set('strictQuery', true);
import * as dotenv from 'dotenv';
dotenv.config();

const database = () => {
  mongoose.connect(process.env.DATABASE_URL, (err) => {
    if (!err) console.log('connection with database established');
  });
};

export default database;
