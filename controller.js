const db = require('./model');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const JWT_SECRET = 'your_jwt_secret_key';

const userSchema = Joi.object({
  name: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().pattern(/^[0-9]+$/).min(10).max(15).required(),
  password: Joi.string().min(6).required(),
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (token == null) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

const registerUser = async (req, res) => {
  const { name, email, phoneNumber, password } = req.body;

  const { error } = userSchema.validate({ name, email, phoneNumber, password });
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (name, email, phoneNumber, password) VALUES (?, ?, ?, ?)';
  try {
    const [results] = await db.query(query, [name, email, phoneNumber, hashedPassword]);
    res.json({ message: 'User created', userId: results.insertId });
  } catch (error) {
    res.json({ error });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  try {
    const [results] = await db.query(query, [email]);
    const user = results[0];
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.json({ error });
  }
};

const getUsers = async (req, res) => {
  const query = 'SELECT * FROM users';
  try {
    const [results] = await db.query(query);
    res.json({ users: results });
  } catch (error) {
    res.json({ error });
  }
};
const getUsersById = async (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM users WHERE id = ?';
    try {
      const [results] = await db.query(query, [id]);
      res.json({ user: results[0] });
    } catch (error) {
      res.json({ error });
    }
  };
  

const userAddSchema = Joi.object({
    name: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    phoneNumber: Joi.string().pattern(/^[0-9]+$/).min(10).max(15).required(),
  });
  
  const addUser = async (req, res) => {
    const { name, email, phoneNumber } = req.body;
  
    // Validate user data
    const { error } = userAddSchema.validate({ name, email, phoneNumber });
    if (error) {
      console.log('Validation Error:', error.details[0].message);
      return res.status(400).json({ error: error.details[0].message });
    }
  
    // Add user to the database
    const query = 'INSERT INTO users (name, email, phoneNumber) VALUES (?, ?, ?)';
    try {
      const [results] = await db.query(query, [name, email, phoneNumber]);
      console.log('User Created with ID:', results.insertId);
      res.status(201).json({ message: 'User created', userId: results.insertId });
    } catch (error) {
      console.error('Database Error:', error);
      res.status(500).json({ error: 'Database error occurred' });
    }
  };  
  
module.exports = {
  registerUser,
  loginUser,
  getUsers: [authenticateToken, getUsers],
  getUsersById: [authenticateToken, getUsersById],
  addUser: [authenticateToken, addUser],
};
