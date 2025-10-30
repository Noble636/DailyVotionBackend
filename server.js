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


app.post('/api/send-otp', async (req, res) => {
	const { email, type } = req.body; 
	if (!email) return res.status(400).json({ error: 'Email required' });

	const accountType = type === 'admin' ? 'admin' : 'user';

	try {
		
		const table = accountType === 'admin' ? 'admins' : 'users';
		const exists = await new Promise((resolve, reject) => {
			db.query(`SELECT id FROM ${table} WHERE email = ? LIMIT 1`, [email], (err, results) => {
				if (err) return reject(err);
				resolve(results && results.length > 0);
			});
		});
		if (!exists) return res.status(404).json({ error: `${accountType} account not found` });

		
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

		
		await new Promise((resolve, reject) => {
			const sql = 'INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)';
			db.query(sql, [email, otp, expiresAt], (err, result) => err ? reject(err) : resolve(result));
		});

	
	await sendOTPEmail(email, otp);

		return res.json({ ok: true, message: 'OTP sent' });
	} catch (err) {
		console.error('send-otp failed:', err && err.message ? err.message : err);
		if (err.code === 'INVALID_GMAIL_REFRESH') {
			return res.status(500).json({ error: 'Email provider refresh token invalid; please reconfigure.' });
		}
		return res.status(500).json({ error: 'Failed to send OTP' });
	}
});


app.post('/api/verify-otp', (req, res) => {
	const { email, otp } = req.body;
	if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
	db.query(
		'SELECT * FROM otps WHERE email = ? AND otp_code = ? AND used = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
		[email, otp],
		(err, results) => {
			if (err) return res.status(500).json({ error: 'DB error' });
			if (results.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
			
			db.query('UPDATE otps SET used = 1 WHERE id = ?', [results[0].id]);
			res.json({ message: 'OTP verified' });
		}
	);
});


app.post('/api/reset-password', async (req, res) => {
	const { email, newPassword, type } = req.body;
	if (!email || !newPassword) return res.status(400).json({ error: 'Email and newPassword required' });
	const accountType = type === 'admin' ? 'admin' : 'user';

	try {
		
		const verified = await new Promise((resolve, reject) => {
			db.query(
				'SELECT id FROM otps WHERE email = ? AND used = 1 AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE) ORDER BY created_at DESC LIMIT 1',
				[email],
				(err, results) => {
					if (err) return reject(err);
					resolve(results && results.length > 0);
				}
			);
		});
		if (!verified) return res.status(403).json({ error: 'OTP not verified or expired' });

		const hashed = await bcrypt.hash(newPassword, 10);
		const table = accountType === 'admin' ? 'admins' : 'users';
		const updateResult = await new Promise((resolve, reject) => {
			db.query(`UPDATE ${table} SET password = ? WHERE email = ?`, [hashed, email], (err, result) => {
				if (err) return reject(err);
				resolve(result);
			});
		});
		if (updateResult.affectedRows === 0) return res.status(404).json({ error: `${accountType} account not found` });

		return res.json({ message: 'Password updated' });
	} catch (err) {
		console.error('reset-password failed:', err && err.message ? err.message : err);
		return res.status(500).json({ error: 'Failed to reset password' });
	}
});


app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


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

app.get('/api/user/:id', (req, res) => {
	const userId = req.params.id;
	db.query('SELECT id, fullName, username, email, mobile, profilePic FROM users WHERE id = ?', [userId], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		if (results.length === 0) return res.status(404).json({ error: 'User not found' });
		res.json(results[0]);
	});
});


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
	// Accept profilePic as file upload or base64 string
	let profilePicBuffer = null;
	if (req.file) {
		profilePicBuffer = fs.readFileSync(req.file.path);
	} else if (req.body.profilePic && typeof req.body.profilePic === 'string' && req.body.profilePic.startsWith('data:image')) {
		// If sent as base64 string
		const base64Data = req.body.profilePic.split(',')[1];
		profilePicBuffer = Buffer.from(base64Data, 'base64');
	}
	if (profilePicBuffer) {
		updateFields.push('profilePic = ?');
		updateValues.push(profilePicBuffer);
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
		db.query('SELECT profilePic FROM users WHERE id = ?', [userId], (err2, rows) => {
			if (err2) return res.status(500).json({ error: 'Database error' });
			res.json({ message: 'Profile updated!', hasProfilePic: !!rows[0]?.profilePic });
		});
	});
});





const buildConnectionOptions = () => {
	const options = {
		host: process.env.DB_HOST,
		user: process.env.DB_USER,
		password: process.env.DB_PASS,
		database: process.env.DB_NAME,
		port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : undefined,
		connectTimeout: process.env.DB_CONNECT_TIMEOUT ? parseInt(process.env.DB_CONNECT_TIMEOUT, 10) : 10000,
	};

	
	const sslEnabled = process.env.DB_SSL === 'true';
	if (sslEnabled) {
		
		if (process.env.DB_SSL_CA_B64) {
			try {
				options.ssl = {
					ca: Buffer.from(process.env.DB_SSL_CA_B64, 'base64'),
					rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false'
				};
			} catch (e) {
				console.error('Failed to decode DB_SSL_CA_B64; proceeding without CA:', e.message);
				options.ssl = { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' };
			}
		} else {
			
			options.ssl = { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' };
		}
	}

	return options;
};

const MAX_RETRIES = process.env.DB_CONNECT_RETRIES ? parseInt(process.env.DB_CONNECT_RETRIES, 10) : 5;
const RETRY_BASE_DELAY = process.env.DB_RETRY_DELAY ? parseInt(process.env.DB_RETRY_DELAY, 10) : 2000;

let db; 

const createDbConnection = () => mysql.createConnection(buildConnectionOptions());

const connectWithRetry = async () => {
	for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
		db = createDbConnection();
		try {
			await new Promise((resolve, reject) => {
				db.connect((err) => {
					if (err) return reject(err);
					resolve();
				});
			});
			console.log('Connected to MySQL database');
			return;
		} catch (err) {
			
			console.error(`MySQL connection attempt ${attempt} failed: ${err && err.code ? err.code : err.message || err}`);
			if (attempt < MAX_RETRIES) {
				const delay = RETRY_BASE_DELAY * attempt;
				console.log(`Retrying MySQL connection in ${delay}ms (attempt ${attempt + 1}/${MAX_RETRIES})`);
				await new Promise((r) => setTimeout(r, delay));
			} else {
				console.error('All MySQL connection attempts failed. Troubleshooting tips:');
				console.error('- Verify DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT are set as environment variables');
				console.error('- If using a managed DB (Aiven/etc.), ensure TLS settings are correct and the CA (DB_SSL_CA_B64) is provided');
				console.error('- Ensure the database allows connections from this host; check allowlists and network settings');
				console.error('Last error:', err && err.code ? `${err.code} - ${err.message}` : err);
				process.exit(1);
			}
		}
	}
};


connectWithRetry();






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


app.post('/api/login', (req, res) => {
	const { emailOrUsername, password } = req.body;
	if (!emailOrUsername || !password) {
		return res.status(400).json({ error: 'Missing credentials' });
	}
	
	
	console.log('Login attempt:', emailOrUsername);
	
	db.query('SELECT * FROM users WHERE username = ?', [emailOrUsername], async (err, userResults) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		console.log('Username match results:', userResults);
		if (userResults.length === 0) {
			
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


app.post('/api/admin/auth', (req, res) => {
	const { adminCode } = req.body;
	if (!adminCode) {
		return res.status(400).json({ error: 'Missing admin code' });
	}
	
	if (adminCode === 'DV-Admin') { 
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

app.get('/api/admin/users', (req, res) => {
	db.query('SELECT id, fullName, username, email, mobile, profilePic, created_at FROM users', [], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json(results);
	});
});


app.get('/api/admin/admins', (req, res) => {
	db.query('SELECT id, fullName, username, email, mobile, adminCode, allowUserLogin, created_at FROM admins', [], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json(results);
	});
});


app.delete('/api/admin/user/:id', (req, res) => {
	const userId = req.params.id;
	db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'User deleted.' });
	});
});


app.delete('/api/admin/admin/:id', (req, res) => {
	const adminId = req.params.id;
	db.query('DELETE FROM admins WHERE id = ?', [adminId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'Admin deleted.' });
	});
});




app.put('/api/admin/admin/:id/code', (req, res) => {
	const adminId = req.params.id;
	const { adminCode } = req.body;
	if (!adminCode) return res.status(400).json({ error: 'Admin code required.' });
	db.query('UPDATE admins SET adminCode = ? WHERE id = ?', [adminCode, adminId], (err, result) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		res.json({ message: 'Admin code updated.' });
	});
});


app.put('/api/admin/admin/:id/loginmethod', (req, res) => {
});

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


app.post('/api/admin/prayer/:id/respond', (req, res) => {
	const prayerId = req.params.id;
	const { response } = req.body;
	console.log('About to update prayer request:', prayerId, response);
	const sql = "UPDATE prayer_requests SET response = ?, status = 'responded' WHERE id = ?";
	db.query(sql, [response, prayerId], (err, result) => {
		if (err) {
			console.error('DB error on prayer respond:', err);
			return res.status(500).json({ error: 'Database error', details: err.message });
		}
		if (result.affectedRows === 0) {
			return res.status(404).json({ error: 'Prayer request not found.' });
		}
		db.query(
			`SELECT p.id, p.user_id as userId, u.fullName as userName, p.text, p.date, p.status, p.response
			 FROM prayer_requests p
			 LEFT JOIN users u ON p.user_id = u.id
			 WHERE p.id = ?`,
			[prayerId],
			(err2, rows) => {
				if (err2) {
					console.error('DB error fetching updated prayer:', err2);
					return res.status(500).json({ error: 'Database error', details: err2.message });
				}
				if (!rows || rows.length === 0) {
					return res.status(404).json({ error: 'Prayer request not found after update.' });
				}
				res.json({ prayer: rows[0] });
			}
		);
	});
});

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


app.post('/api/admin/reflection', (req, res) => {
	const { adminId, message, userIds } = req.body;
	if (!adminId || !message || !Array.isArray(userIds) || userIds.length === 0) {
		return res.status(400).json({ error: 'Missing required fields' });
	}
	
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

app.get('/api/user/:id/reflections', (req, res) => {
	const userId = req.params.id;
	
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


app.post('/api/user/:userId/reflection/:reflectionId/response', (req, res) => {
	const userId = req.params.userId;
	const reflectionId = req.params.reflectionId;
	const { response } = req.body;
	if (!response) return res.status(400).json({ error: 'Response required.' });
	
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


app.get('/api/admin/reflections/responses', (req, res) => {
	
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



app.post('/api/check-account', async (req, res) => {
	const { email, type } = req.body;
	if (!email) return res.status(400).json({ error: 'Email required' });
	const accountType = type === 'admin' ? 'admin' : 'user';
	const table = accountType === 'admin' ? 'admins' : 'users';
	try {
		const exists = await new Promise((resolve, reject) => {
			db.query(`SELECT id FROM ${table} WHERE email = ? LIMIT 1`, [email], (err, results) => {
				if (err) return reject(err);
				resolve(results && results.length > 0);
			});
		});
		return res.json({ exists });
	} catch (err) {
		console.error('check-account failed:', err && err.message ? err.message : err);
		return res.status(500).json({ error: 'Database error' });
	}
});


app.post('/api/user/forgot-password/verify-email', async (req, res) => {
	
	
	const { email: identifier } = req.body; 
	if (!identifier) return res.status(400).json({ error: 'Email or username required' });
	try {
		
		const userRows = await new Promise((resolve, reject) => {
			db.query(
				'SELECT id, fullName, username, email FROM users WHERE email = ? OR username = ? LIMIT 1',
				[identifier, identifier],
				(err, results) => err ? reject(err) : resolve(results)
			);
		});
		if (!userRows || userRows.length === 0) return res.status(404).json({ error: 'User not found' });

		const user = userRows[0];
		const email = user.email; 

		
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
		await new Promise((resolve, reject) => {
			db.query('INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt], (err, r) => err ? reject(err) : resolve(r));
		});
		
		await sendOTPEmail(email, otp);
		return res.json({ message: 'OTP sent', userDetails: user });
	} catch (err) {
		console.error('user/forgot-password/verify-email failed:', err && err.message ? err.message : err);
		if (err && err.code === 'INVALID_GMAIL_REFRESH') {
			return res.status(500).json({ error: 'Email provider refresh token invalid; please reconfigure.' });
		}
		return res.status(500).json({ error: 'Failed to send OTP' });
	}
});


app.post('/api/user/forgot-password/verify-otp', (req, res) => {
	const { email, otp } = req.body;
	if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
	db.query('SELECT * FROM otps WHERE email = ? AND otp_code = ? AND used = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1', [email, otp], (err, results) => {
		if (err) return res.status(500).json({ error: 'DB error' });
		if (!results || results.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
		db.query('UPDATE otps SET used = 1 WHERE id = ?', [results[0].id]);
		
		return res.json({ message: 'OTP verified' });
	});
});


app.post('/api/user/forgot-password/reset-password', async (req, res) => {
	const { email, newPassword } = req.body;
	if (!email || !newPassword) return res.status(400).json({ error: 'Email and newPassword required' });
	try {
		
		const verified = await new Promise((resolve, reject) => {
			db.query('SELECT id FROM otps WHERE email = ? AND used = 1 AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE) ORDER BY created_at DESC LIMIT 1', [email], (err, results) => err ? reject(err) : resolve(results && results.length > 0));
		});
		if (!verified) return res.status(403).json({ error: 'OTP not verified or expired' });
		const hashed = await bcrypt.hash(newPassword, 10);
		const result = await new Promise((resolve, reject) => {
			db.query('UPDATE users SET password = ? WHERE email = ?', [hashed, email], (err, r) => err ? reject(err) : resolve(r));
		});
		if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
		return res.json({ message: 'Password updated' });
	} catch (err) {
		console.error('user reset-password failed:', err && err.message ? err.message : err);
		return res.status(500).json({ error: 'Failed to reset password' });
	}
});



app.post('/api/admin/forgot-password/verify-email', async (req, res) => {
	
	const { email: identifier } = req.body;
	if (!identifier) return res.status(400).json({ error: 'Email or username required' });
	try {
		const adminRows = await new Promise((resolve, reject) => {
			db.query('SELECT id, fullName, username, email FROM admins WHERE email = ? OR username = ? LIMIT 1', [identifier, identifier], (err, results) => err ? reject(err) : resolve(results));
		});
		if (!adminRows || adminRows.length === 0) return res.status(404).json({ error: 'Admin not found' });
		const admin = adminRows[0];
		const email = admin.email;
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
		await new Promise((resolve, reject) => {
			db.query('INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt], (err, r) => err ? reject(err) : resolve(r));
		});
		await sendOTPEmail(email, otp);
		return res.json({ message: 'OTP sent', adminDetails: admin });
	} catch (err) {
		console.error('admin/forgot-password/verify-email failed:', err && err.message ? err.message : err);
		if (err && err.code === 'INVALID_GMAIL_REFRESH') {
			return res.status(500).json({ error: 'Email provider refresh token invalid; please reconfigure.' });
		}
		return res.status(500).json({ error: 'Failed to send OTP' });
	}
});


app.post('/api/admin/forgot-password/verify-otp', (req, res) => {
	const { email, otp } = req.body;
	if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
	db.query('SELECT * FROM otps WHERE email = ? AND otp_code = ? AND used = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1', [email, otp], (err, results) => {
		if (err) return res.status(500).json({ error: 'DB error' });
		if (!results || results.length === 0) return res.status(400).json({ error: 'Invalid or expired OTP' });
		db.query('UPDATE otps SET used = 1 WHERE id = ?', [results[0].id]);
		return res.json({ message: 'OTP verified' });
	});
});


app.post('/api/admin/forgot-password/reset-password', async (req, res) => {
	const { email, newPassword } = req.body;
	if (!email || !newPassword) return res.status(400).json({ error: 'Email and newPassword required' });
	try {
		const verified = await new Promise((resolve, reject) => {
			db.query('SELECT id FROM otps WHERE email = ? AND used = 1 AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE) ORDER BY created_at DESC LIMIT 1', [email], (err, results) => err ? reject(err) : resolve(results && results.length > 0));
		});
		if (!verified) return res.status(403).json({ error: 'OTP not verified or expired' });
		const hashed = await bcrypt.hash(newPassword, 10);
		const result = await new Promise((resolve, reject) => {
			db.query('UPDATE admins SET password = ? WHERE email = ?', [hashed, email], (err, r) => err ? reject(err) : resolve(r));
		});
		if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
		return res.json({ message: 'Password updated' });
	} catch (err) {
		console.error('admin reset-password failed:', err && err.message ? err.message : err);
		return res.status(500).json({ error: 'Failed to reset password' });
	}
});

// Serve profilePic BLOB as base64 image
app.get('/api/user/:id/profile-pic', (req, res) => {
	const userId = req.params.id;
	db.query('SELECT profilePic FROM users WHERE id = ?', [userId], (err, results) => {
		if (err) return res.status(500).json({ error: 'Database error' });
		if (!results.length || !results[0].profilePic) {
			return res.status(404).json({ error: 'No profile picture found' });
		}
		const imgBuffer = results[0].profilePic;
		// Detect image type (default to jpeg)
		let mimeType = 'image/jpeg';
		// Optionally, you can store mimeType in DB for more accuracy
		// For now, just use jpeg
		const base64Img = imgBuffer.toString('base64');
		res.json({ base64: `data:${mimeType};base64,${base64Img}` });
	});
});