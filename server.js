// server.js - Main server file
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_jwt_secret';

app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'Role_Authentication'
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// User Login API
app.post('/auth/login', (req, res) => {
    const { email, password, role } = req.body;
    const query = "SELECT * FROM users WHERE email = ? AND role = ?";
    
    db.query(query, [email, role], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ user_id: user.user_id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token, role: user.role });
    });
});

// Middleware for Authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Unauthorized' });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

// Middleware for Role Authorization
const authorizeSchool = (req, res, next) => {
    if (req.user.role !== 'school') {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
};

// Role-Based Dashboard Routing
app.get('/dashboard', authenticate, (req, res) => {
    switch (req.user.role) {
        case 'school':
            res.json({ message: 'Welcome to the School Dashboard' });
            break;
        case 'parent':
            res.json({ message: 'Welcome to the Parent Dashboard' });
            break;
        case 'student':
            res.json({ message: 'Welcome to the Student Dashboard' });
            break;
        default:
            res.status(403).json({ error: 'Invalid role' });
    }
});

app.get('/student/achievements/:student_id', authenticate, (req, res) => {
    const { student_id } = req.params;

    if (req.user.role === 'parent') {
        // Check if the parent is linked to this student
        const parentCheckQuery = "SELECT * FROM parent_student WHERE parent_id = ? AND student_id = ?";
        db.query(parentCheckQuery, [req.user.user_id, student_id], (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (results.length === 0) return res.status(403).json({ error: 'Access denied' });

            // Fetch achievements
            const query = "SELECT * FROM achievements WHERE student_id = ?";
            db.query(query, [student_id], (err, results) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ achievements: results });
            });
        });
    } else if (req.user.role === 'student' && req.user.user_id == student_id) {
        // Students can only fetch their own achievements
        const query = "SELECT * FROM achievements WHERE student_id = ?";
        db.query(query, [student_id], (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ achievements: results });
        });
    } else {
        return res.status(403).json({ error: 'Access denied' });
    }
});

// Add Students, Parents, and Achievements (Only School Role)
app.post('/add/student', authenticate, authorizeSchool, (req, res) => {
    const { name, email, password, school_id } = req.body; // Accept school_id
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const query = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'student')";
    db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const user_id = result.insertId; // Get new student user_id
        const studentQuery = "INSERT INTO students (user_id, school_id) VALUES (?, ?)";

        db.query(studentQuery, [user_id, school_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Student added successfully' });
        });
    });
});



/*app.post('/add/parent', authenticate, authorizeSchool, (req, res) => {
    const { name, email, password, student_id } = req.body; // Accept student_id
    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'parent')";
    db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const parent_id = result.insertId; // Get new parent user_id
        const parentStudentQuery = "INSERT INTO parent_student (parent_id, student_id) VALUES (?, ?)";

        db.query(parentStudentQuery, [parent_id, student_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Parent added and linked to student successfully' });
        });
    });
}); */
app.post('/add/parent', authenticate, authorizeSchool, (req, res) => {
    const { name, email, password, student_id } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert the parent into the users table
    const queryUser = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'parent')";
    db.query(queryUser, [name, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const newParentId = result.insertId;  // Get the newly inserted parent user_id

        // Now link the parent with the student in the parent_student table
        const queryLink = "INSERT INTO parent_student (parent_id, student_id) VALUES (?, ?)";
        db.query(queryLink, [newParentId, student_id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Parent added successfully' });
        });
    });
});



app.post('/add/achievement', authenticate, authorizeSchool, (req, res) => {
    const { student_id, title, description, date_achieved } = req.body;
    const query = "INSERT INTO achievements (student_id, title, description, date_achieved) VALUES (?, ?, ?, ?)";
    db.query(query, [student_id, title, description, date_achieved], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Achievement added successfully' });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
