// seed.js - Initializes and Seeds the Database
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '1234',
    database: 'Role_Authentication'
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err);
        process.exit(1); // Stop server if DB fails
    }
    console.log('Connected to MySQL');
});

const seedDB = async () => {
    try {
        const hashedPassword = bcrypt.hashSync('password123', 10);
        const schoolUser = ['Admin School', 'admin@school.com', hashedPassword, 'school'];
        
        await new Promise((resolve, reject) => {
            db.query("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", schoolUser, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        console.log('School user seeded successfully');
    } catch (error) {
        console.error('Error during seeding:', error);
    } finally {
        db.end();
    }
};

seedDB();


seedDB();
