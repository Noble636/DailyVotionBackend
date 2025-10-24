require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 5000;
const crypto = require('crypto');
const { sendOTPEmail } = require('./mailer');
// --- OTP GENERATION & EMAIL ENDPOINT ---
// POST /api/send-otp { email }
app.post('/api/send-otp', async (req, res) => {
	const { email } = req.body;
	if (!email) return res.status(400).json({ error: 'Email required' });
	// Check if user or admin exists
	db.query(
		'SELECT id FROM users WHERE email = ? UNION SELECT id FROM admins WHERE email = ?',
		[email, email],
		async (err, results) => {
			if (err) return res.status(500).json({ error: 'DB error' });
			if (results.length === 0) return res.status(404).json({ error: 'Email not found' });
			// Generate 6-digit OTP
			const otp = ('' + Math.floor(100000 + Math.random() * 900000));
			const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min
			// Store OTP in DB
			db.query(
				'INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)',
				[email, otp, expiresAt],
				async (err2) => {
					if (err2) return res.status(500).json({ error: 'DB error (otp)' });
					try {
						await sendOTPEmail(email, otp);
						res.json({ message: 'OTP sent' });
					} catch (e) {
						res.status(500).json({ error: 'Failed to send email' });
					}
				}
			);
		}
	);
});

// POST /api/verify-otp { email, otp }
app.post('/api/verify-otp', (req, res) => {
	const { email, otp } = req.body;
	if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
	db.query(
		'SELECT * FROM otps WHERE email = ? AND otp_code = ? AND used = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
		[email, otp],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'DB error' });
			if (results.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
			// Mark OTP as used
			db.query('UPDATE otps SET used = 1 WHERE id = ?', [results[0].id]);
			res.json({ message: 'OTP verified' });
		}
	);
});


app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ...existing code...

// Admin login endpoint (moved after app initialization)
app.post('/api/admin/login', (req, res) => {
	const { emailOrUsername, password } = req.body;
	if (!emailOrUsername || !password) {
		return res.status(400).json({ error: 'Missing credentials' });
	}
	db.query(
		'SELECT * FROM admins WHERE email = ? OR username = ?',
		[emailOrUsername, emailOrUsername],
		async (err, adminResults) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			if (adminResults.length === 0) {
				return res.status(401).json({ error: 'Invalid credentials' });
			}
			const admin = adminResults[0];
			const match = await bcrypt.compare(password, admin.password);
			if (!match) {
				return res.status(401).json({ error: 'Invalid credentials' });
			}
			return res.json({
				id: admin.id,
				fullName: admin.fullName,
				username: admin.username,
				email: admin.email,
				type: 'admin'
			});
		}
	);
});

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer setup for profile picture upload
const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		const uploadDir = path.join(__dirname, 'uploads');
		if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
		cb(null, uploadDir);
	},
	filename: function (req, file, cb) {
		cb(null, Date.now() + '-' + file.originalname);
	}
});
const upload = multer({ storage });
// Get user info
app.get('/api/user/:id', (req, res) => {
	const userId = req.params.id;
	db.query('SELECT id, fullName, username, email, mobile, profilePic FROM users WHERE id = ?', [userId], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		if (results.length === 0) return res.status(404).json({ error: 'User not found' });
		res.json(results[0]);
	});
});

// Update user info (with profile picture)
app.put('/api/user/:id', upload.single('profilePic'), async (req, res) => {
	const userId = req.params.id;
	const { fullName, username, email, mobile, password } = req.body;
	let updateFields = [];
	let updateValues = [];
	if (fullName) { updateFields.push('fullName = ?'); updateValues.push(fullName); }
	if (username) { updateFields.push('username = ?'); updateValues.push(username); }
	if (email) { updateFields.push('email = ?'); updateValues.push(email); }
	if (mobile) { updateFields.push('mobile = ?'); updateValues.push(mobile); }
	if (password) {
		const hashedPassword = await bcrypt.hash(password, 10);
		updateFields.push('password = ?'); updateValues.push(hashedPassword);
	}
	if (req.file) {
		const profilePicPath = '/uploads/' + req.file.filename;
		updateFields.push('profilePic = ?'); updateValues.push(profilePicPath);
	}
	if (updateFields.length === 0) return res.status(400).json({ error: 'No fields to update' });
	updateValues.push(userId);
		db.query(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, updateValues, (err, result) => {
			if (err) {
				if (err.code === 'ER_DUP_ENTRY') {
					return res.status(400).json({ error: 'Email or username already exists' });
				}
				return res.status(500).json({ error: 'Database error' });
			}
			// Return updated profilePic path for immediate frontend refresh
			db.query('SELECT profilePic FROM users WHERE id = ?', [userId], (err2, rows) => {
				if (err2) return res.status(500).json({ error: 'Database error' });
				res.json({ message: 'Profile updated!', profilePic: rows[0]?.profilePic });
			});
		});
});

// MySQL connection
const db = mysql.createConnection({
	host: process.env.DB_HOST,
	user: process.env.DB_USER,
	password: process.env.DB_PASS,
	database: process.env.DB_NAME,
	port: process.env.DB_PORT
});

db.connect((err) => {
	if (err) throw err;
	console.log('Connected to MySQL database');
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
	const { fullName, username, email, mobile, password } = req.body;
	if (!fullName || !username || !email || !password) {
		return res.status(400).json({ error: 'Missing required fields' });
	}
	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		db.query(
			'INSERT INTO users (fullName, username, email, mobile, password) VALUES (?, ?, ?, ?, ?)',
			[fullName, username, email, mobile, hashedPassword],
			(err, result) => {
				if (err) {
					if (err.code === 'ER_DUP_ENTRY') {
						return res.status(400).json({ error: 'Email or username already exists' });
					}
					return res.status(500).json({ error: 'Database error' });
				}
				res.status(201).json({ message: 'User registered successfully', id: result.insertId });
			}
		);
	} catch (err) {
		res.status(500).json({ error: 'Server error' });
	}
});

// Login endpoint
app.post('/api/login', (req, res) => {
	const { emailOrUsername, password } = req.body;
	if (!emailOrUsername || !password) {
		return res.status(400).json({ error: 'Missing credentials' });
	}
	// Only allow login for users in users table
	// Debug logging
	console.log('Login attempt:', emailOrUsername);
	// Try to match username first
	db.query('SELECT * FROM users WHERE username = ?', [emailOrUsername], async (err, userResults) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		console.log('Username match results:', userResults);
		if (userResults.length === 0) {
			// If not found, try email
			db.query('SELECT * FROM users WHERE email = ?', [emailOrUsername], async (err2, userResults2) => {
				if (err2) return res.status(500).json({ error: 'Database error' });
				console.log('Email match results:', userResults2);
				if (userResults2.length === 0) {
					return res.status(401).json({ error: 'Invalid credentials' });
				}
				const user = userResults2[0];
				console.log('Logging in as (email):', user.username, user.email);
				const match = await bcrypt.compare(password, user.password);
				if (!match) {
					return res.status(401).json({ error: 'Invalid credentials' });
				}
				return res.json({
					id: user.id,
					fullName: user.fullName,
					username: user.username,
					email: user.email,
					type: 'user'
				});
			});
		} else {
			const user = userResults[0];
			console.log('Logging in as (username):', user.username, user.email);
			const match = await bcrypt.compare(password, user.password);
			if (!match) {
				return res.status(401).json({ error: 'Invalid credentials' });
			}
			return res.json({
				id: user.id,
				fullName: user.fullName,
				username: user.username,
				email: user.email,
				type: 'user'
			});
		}
	});
});


// Admin registration endpoint
app.post('/api/admin/register', async (req, res) => {
	const { fullName, username, email, mobile, password, adminCode } = req.body;
	if (!fullName || !username || !email || !password || !adminCode) {
		return res.status(400).json({ error: 'Missing required fields' });
	}
	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		db.query(
			'INSERT INTO admins (fullName, username, email, mobile, password, adminCode) VALUES (?, ?, ?, ?, ?, ?)',
			[fullName, username, email, mobile, hashedPassword, adminCode],
			(err, result) => {
				if (err) {
					if (err.code === 'ER_DUP_ENTRY') {
						return res.status(400).json({ error: 'Email or username already exists' });
					}
					return res.status(500).json({ error: 'Database error' });
				}
				res.status(201).json({ message: 'Admin registered successfully' });
			}
		);
	} catch (err) {
		res.status(500).json({ error: 'Server error' });
	}
});

// Admin code authentication endpoint
app.post('/api/admin/auth', (req, res) => {
	const { adminCode } = req.body;
	if (!adminCode) {
		return res.status(400).json({ error: 'Missing admin code' });
	}
	// Master code bypass
	if (adminCode === 'DV-Admin') { // pwede palitan
		return res.json({ success: true, message: 'Master code accepted' });
	}
	db.query(
		'SELECT * FROM admins WHERE adminCode = ?',
		[adminCode],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			if (results.length === 0) {
				return res.status(401).json({ error: 'Invalid admin code' });
			}
			res.json({ success: true, message: 'Admin code accepted' });
		}
	);
});

app.listen(PORT, () => {
		console.log(`Server running on port ${PORT}`);
});
// Get all users
app.get('/api/admin/users', (req, res) => {
	db.query('SELECT id, fullName, username, email, mobile, profilePic, created_at FROM users', [], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json(results);
	});
});

// Get all admins
app.get('/api/admin/admins', (req, res) => {
	db.query('SELECT id, fullName, username, email, mobile, adminCode, allowUserLogin, created_at FROM admins', [], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json(results);
	});
});

// Delete user (cascade)
app.delete('/api/admin/user/:id', (req, res) => {
	const userId = req.params.id;
	db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'User deleted.' });
	});
});

// Delete admin (cascade)
app.delete('/api/admin/admin/:id', (req, res) => {
	const adminId = req.params.id;
	db.query('DELETE FROM admins WHERE id = ?', [adminId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'Admin deleted.' });
	});
});

// Edit user role (set as admin)

// Edit admin code
app.put('/api/admin/admin/:id/code', (req, res) => {
	const adminId = req.params.id;
	const { adminCode } = req.body;
	if (!adminCode) return res.status(400).json({ error: 'Admin code required.' });
	db.query('UPDATE admins SET adminCode = ? WHERE id = ?', [adminCode, adminId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'Admin code updated.' });
	});
});

// Toggle admin login method (allowUserLogin)
app.put('/api/admin/admin/:id/loginmethod', (req, res) => {
});
// User: submit prayer request
app.post('/api/user/:id/prayer', (req, res) => {
	const userId = req.params.id;
	const { text } = req.body;
	if (!text) return res.status(400).json({ error: 'Prayer text required.' });
	const date = new Date().toISOString().slice(0, 10);
	db.query(
		'INSERT INTO prayer_requests (user_id, text, date) VALUES (?, ?, ?)',
		[userId, text, date],
		(err, result) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			db.query('SELECT * FROM prayer_requests WHERE id = ?', [result.insertId], (err2, rows) => {
				if (err2) return res.status(500).json({ error: 'Database error' });
				res.status(201).json({ prayer: rows[0] });
			});
		}
	);
});

// User: get own prayer requests
app.get('/api/user/:id/prayer', (req, res) => {
	const userId = req.params.id;
	db.query(
		'SELECT id, text, date, status, response FROM prayer_requests WHERE user_id = ? ORDER BY date DESC, created_at DESC',
		[userId],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});

// Admin: get all prayer requests
app.get('/api/admin/prayer', (req, res) => {
	db.query(
		`SELECT p.id, p.user_id as userId, u.fullName as userName, p.text, p.date, p.status, p.response
		 FROM prayer_requests p
		 LEFT JOIN users u ON p.user_id = u.id
		 ORDER BY p.date DESC, p.created_at DESC`,
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});

// Admin: respond to prayer request
app.post('/api/admin/prayer/:id/respond', (req, res) => {
	const prayerId = req.params.id;
	const { response } = req.body;
	if (!response) return res.status(400).json({ error: 'Response required.' });
	db.query(
		'UPDATE prayer_requests SET response = ?, status = "responded" WHERE id = ?',
		[response, prayerId],
		(err, result) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			db.query(
				`SELECT p.id, p.user_id as userId, u.fullName as userName, p.text, p.date, p.status, p.response
				 FROM prayer_requests p
				 LEFT JOIN users u ON p.user_id = u.id
				 WHERE p.id = ?`,
				[prayerId],
				(err2, rows) => {
					if (err2) return res.status(500).json({ error: 'Database error' });
					res.json({ prayer: rows[0] });
				}
			);
		}
	);
});
// User: submit app feedback
app.post('/api/user/:id/feedback', (req, res) => {
	const userId = req.params.id;
	const { text } = req.body;
	if (!text) return res.status(400).json({ error: 'Feedback text required.' });
	const date = new Date().toISOString().slice(0, 10);
	db.query(
		'INSERT INTO feedback (user_id, text, date) VALUES (?, ?, ?)',
		[userId, text, date],
		(err, result) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.status(201).json({ message: 'Feedback submitted!' });
		}
	);
});

// Admin: get all feedback (hide user name)
app.get('/api/admin/feedback', (req, res) => {
	db.query(
		'SELECT text, date FROM feedback ORDER BY date DESC, id DESC',
		[],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});
// Save journal entry for user
app.post('/api/user/:id/journal', (req, res) => {
	const userId = req.params.id;
	const { date, scripture, observation, application, prayer } = req.body;
	if (!date || !scripture) {
		return res.status(400).json({ error: 'Date and scripture are required.' });
	}
	db.query(
		'INSERT INTO journals (user_id, date, scripture, observation, application, prayer) VALUES (?, ?, ?, ?, ?, ?)',
		[userId, date, scripture, observation, application, prayer],
		(err, result) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.status(201).json({ message: 'Journal entry saved!' });
		}
	);
});

// Get latest journal entry for user
app.get('/api/user/:id/journal/latest', (req, res) => {
	const userId = req.params.id;
	db.query(
		'SELECT date, scripture, observation, application, prayer FROM journals WHERE user_id = ? ORDER BY date DESC, created_at DESC LIMIT 1',
		[userId],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			if (results.length === 0) return res.json({ message: 'No journal entries yet.' });
			res.json(results[0]);
		}
	);
});

// Get all journal entries for user (for history)
app.get('/api/user/:id/journal', (req, res) => {
	const userId = req.params.id;
	db.query(
		'SELECT date, scripture, observation, application, prayer FROM journals WHERE user_id = ? ORDER BY date DESC, created_at DESC',
		[userId],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});

// Admin: deliver reflection activity to selected users
app.post('/api/admin/reflection', (req, res) => {
	const { adminId, message, userIds } = req.body;
	if (!adminId || !message || !Array.isArray(userIds) || userIds.length === 0) {
		return res.status(400).json({ error: 'Missing required fields' });
	}
	// Insert a reflection for each selected user
	const values = userIds.map(userId => [adminId, userId, message]);
	db.beginTransaction(err => {
		if (err) {
			console.error('Transaction error:', err);
			return res.status(500).json({ error: 'Database error', details: err });
		}
		const insertPromises = values.map(([adminId, userId, message]) => {
			return new Promise((resolve, reject) => {
				db.query(
					'INSERT INTO reflections (admin_id, user_id, message, sent_at) VALUES (?, ?, ?, NOW())',
					[adminId, userId, message],
					(err, result) => {
						if (err) {
							console.error('Insert reflection error:', { adminId, userId, message, err });
							return reject(err);
						}
						resolve();
					}
				);
			});
		});
		Promise.all(insertPromises)
			.then(() => {
				db.commit(err => {
					if (err) {
						console.error('Commit error:', err);
						return res.status(500).json({ error: 'Database error', details: err });
					}
					res.json({ success: true });
				});
			})
			.catch(err => {
				console.error('Reflection delivery failed, rolling back:', err);
				db.rollback(() => {
					res.status(500).json({ error: 'Database error', details: err });
				});
			});
	});
});
// Get reflections sent to user and their responses
app.get('/api/user/:id/reflections', (req, res) => {
	const userId = req.params.id;
	// Get latest reflections sent to this user and any response
	db.query(
		`SELECT r.id, r.message, r.sent_at, a.fullName as adminName, rr.response, rr.responded_at
		 FROM reflections r
		 JOIN admins a ON r.admin_id = a.id
		 LEFT JOIN reflection_responses rr ON rr.reflection_id = r.id AND rr.user_id = ?
		 WHERE r.user_id = ?
		 ORDER BY r.sent_at DESC LIMIT 5`,
		[userId, userId],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});

// User: submit reflection response
app.post('/api/user/:userId/reflection/:reflectionId/response', (req, res) => {
	const userId = req.params.userId;
	const reflectionId = req.params.reflectionId;
	const { response } = req.body;
	if (!response) return res.status(400).json({ error: 'Response required.' });
	// Only one response per user per reflection: update if exists, else insert
	db.query(
		`INSERT INTO reflection_responses (reflection_id, user_id, response, responded_at)
		 VALUES (?, ?, ?, NOW())
		 ON DUPLICATE KEY UPDATE response = VALUES(response), responded_at = NOW()`,
		[reflectionId, userId, response],
		(err, result) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json({ success: true, message: 'Response successful' });
		}
	);
});

// Admin: get all user reflection responses (for ManageContent)
app.get('/api/admin/reflections/responses', (req, res) => {
	// Returns all reflections, all user responses, and user info
	db.query(
		`SELECT r.id as reflectionId, r.message, r.sent_at, a.fullName as adminName,
				u.id as userId, u.fullName as userName, rr.response, rr.responded_at
		 FROM reflections r
		 JOIN admins a ON r.admin_id = a.id
		 LEFT JOIN reflection_responses rr ON rr.reflection_id = r.id
		 LEFT JOIN users u ON rr.user_id = u.id
		 ORDER BY r.sent_at DESC, rr.responded_at DESC`,
		[],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'Database error' });
			res.json(results);
		}
	);
});