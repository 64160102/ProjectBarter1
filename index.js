const express = require('express');
const http = require('http');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const fs = require('fs');
const dbConnection = require('./database');
const socketIo = require('socket.io');



// const someModule = require('./someModule');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000  // 1hr
}));

// Set up multer for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


// Middleware to check if user is logged in
const ifNotLoggedIn = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.render('login-register');
    }
    next();
};

const ifLoggedIn = (req, res, next) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/home');
    }
    next();
};

// Root page
app.get('/', ifNotLoggedIn, (req, res) => {
    console.log('User name:', req.session.userName); // Log the username
    dbConnection.execute("SELECT products.*, users.name AS user_name FROM products JOIN users ON products.user_id = users.id")
        .then(([rows]) => {
            res.render('home', {
                name: req.session.userName,
                products: rows
            });
        })
        .catch(err => {
            console.log(err);
        });
});

// Upload product page
// Upload product page
app.get('/upload', ifNotLoggedIn, (req, res) => {
    res.render('upload', {
        name: req.session.userName
    });
});

app.post('/upload', ifNotLoggedIn, upload.single('product_image'), (req, res) => {
    if (!req.file) {
        return res.render('upload', {
            msg: 'Error: No File Selected!',
            name: req.session.userName
        });
    }

    const { product_name, product_description, product_location, product_status } = req.body;
    const product_image = `/uploads/${req.file.filename}`;

    dbConnection.execute(
        'INSERT INTO products (name, description, image, location, status, user_id) VALUES (?, ?, ?, ?, ?, ?)',
        [product_name, product_description, product_image, product_location, product_status, req.session.userID]
    ).then(result => {
        res.redirect('/');
    }).catch(err => {
        console.error(err);
        res.send('Error occurred while uploading the product.');
    });
});



// Register page
app.post('/register', ifLoggedIn, [
    body('user_email', 'Invalid Email Address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT email FROM users WHERE email =?', [value])
            .then(([rows]) => {
                if (rows.length > 0) {
                    return Promise.reject('This email already in use!');
                }
                return true;
            });
    }),
    body('user_name', 'Username is empty!').trim().not().isEmpty(),
    body('user_pass', 'The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),

], (req, res, next) => {
    const validation_result = validationResult(req);
    const { user_name, user_pass, user_email } = req.body;

    if (validation_result.isEmpty()) {
        bcrypt.hash(user_pass, 12).then((hash_pass) => {
            dbConnection.execute("INSERT INTO users (name, email, password) VALUES(?,?,?)", [user_name, user_email, hash_pass])
                .then(result => {
                    res.send('<div style="font-size: 2rem; text-align: center;">Your account has been created successfully, Now you can <a href="/">Login</a></div>');
                }).catch(err => {
                    if (err) throw err;
                });
        }).catch(err => {
            if (err) throw err;
        });

    } else {
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });

        res.render('register', {
            register_error: allErrors,
            old_data: req.body
        });
    }
});

// Login page
app.post('/', ifLoggedIn, [
    body('user_email').custom((value) => {
        return dbConnection.execute("SELECT email FROM users WHERE email =?", [value])
            .then(([rows]) => {
                if (rows.length == 1) {
                    return true;
                }
                return Promise.reject('Invalid Email Address!');
            });
    }),
    body('user_pass', 'Password is empty').trim().not().isEmpty(),

], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, user_email } = req.body;
    if (validation_result.isEmpty()) {
        dbConnection.execute("SELECT * FROM users WHERE email = ?", [user_email])
            .then(([rows]) => {

                bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                    if (compare_result === true) {
                        req.session.isLoggedIn = true;
                        req.session.userID = rows[0].id; // Store userID in session
                        req.session.userName = rows[0].name; // Store username in session
                        res.redirect('/');
                    } else {
                        res.render('login-register', {
                            login_errors: ['Invalid Password']
                        });
                    }
                }).catch(err => {
                    if (err) throw err;
                });
            }).catch(err => {
                if (err) throw err;
            });
    } else {
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });

        res.render('login-register', {
            login_errors: allErrors
        });
    }
});

// Logout

app.get('/logout', (req, res) => {

    req.session = null;
    res.redirect('/');
});

// Product details page
app.get('/product/:id', (req, res) => {
    const productId = req.params.id;
    const userID = req.session.userID; // ดึง userID จากเซสชัน
    dbConnection.execute("SELECT products.*, users.name AS user_name, users.profile_image FROM products JOIN users ON products.user_id = users.id WHERE products.id = ?", [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                res.render('product', {
                    product: rows[0],
                    name: req.session.userName, // ส่งค่าชื่อผู้ใช้ไปยังหน้า product.ejs
                    user: {
                        profile_image: rows[0].profile_image // ส่งข้อมูลรูปโปรไฟล์ผู้ใช้ไปที่หน้า product.ejs
                    },
                    userID: userID // ส่งค่า userID ไปยังหน้า product.ejs
                });
            } else {
                res.status(404).send('Product not found');
            }
        }).catch(err => {
            console.error(err);
            res.status(500).send('Error occurred while fetching the product.');
        });
});




// Register page
app.get('/register', (req, res) => {
    res.render('register'); // Render the 'register.ejs' template
});



// Settings page
app.get('/settings', ifNotLoggedIn, (req, res) => {
    const userID = req.session.userID;

    const userQuery = 'SELECT * FROM users WHERE id = ?';
    const settingsQuery = 'SELECT * FROM settinguser WHERE user_id = ?';

    Promise.all([
        dbConnection.execute(userQuery, [userID]),
        dbConnection.execute(settingsQuery, [userID])
    ]).then(([userRows, settingsRows]) => {
        if (userRows[0].length > 0) {
            const user = userRows[0][0];
            const settings = settingsRows[0][0] || {};
            res.render('settings', {
                name: req.session.userName,
                user: user,
                settings: settings
            });
        } else {
            res.status(404).send('User not found');
        }
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while fetching user details.');
    });
});



app.post('/settings', ifNotLoggedIn, upload.single('profile_image'), (req, res) => {
    const userID = req.session.userID;
    const {
        name = '',
        email = '',
        phone = '',
        gender = '',
        day = 1,
        month = 1,
        year = 1900,
        address_line1 = '',
        address_line2 = '',
        city = '',
        state = '',
        postal_code = '',
        country = '',
        existing_profile_image = ''
    } = req.body;

    let profile_image = existing_profile_image;
    if (req.file) {
        profile_image = `/uploads/${req.file.filename}`;
    }

    // Update user table
    const userUpdateQuery = `
        UPDATE users 
        SET name = ?, email = ?, phone = ?, gender = ?, dob_day = ?, dob_month = ?, dob_year = ?, profile_image = ?, address_line1 = ? , address_line2 = ? 
         WHERE id = ?`;

    // Check if settings exist for the user
    const settingsSelectQuery = 'SELECT * FROM settinguser WHERE user_id = ?';
    const settingsInsertQuery = `
        INSERT INTO settinguser (user_id, address_line1, address_line2, city, state, postal_code, country, phone, gender)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const settingsUpdateQuery = `
        UPDATE settinguser
        SET address_line1 = ?, address_line2 = ?, city = ?, state = ?, postal_code = ?, country = ?, phone = ?, gender = ?
        WHERE user_id = ?
    `;

    dbConnection.execute(settingsSelectQuery, [userID])
        .then(([settingsRows]) => {
            if (settingsRows.length > 0) {
                // Update existing settings
                return dbConnection.execute(settingsUpdateQuery, [address_line1, address_line2, city, state, postal_code, country, phone, gender, userID]);
            } else {
                // Insert new settings
                return dbConnection.execute(settingsInsertQuery, [userID, address_line1, address_line2, city, state, postal_code, country, phone, gender]);
            }
        })
        .then(() => {
            // Update user details
            return dbConnection.execute(userUpdateQuery, [name, email, phone, gender, day, month, year, profile_image,address_line1,address_line2, userID]);
        })
        .then(() => {
            // Optionally, update the session with the new name
            req.session.userName = name;
            res.redirect('/settings'); // Redirect to settings page after saving
        })
        .catch(err => {
            console.error(err);
            // Handle errors: log the error, notify the user, etc.
            res.status(500).send('Error occurred while updating user details.');
        });
});







// การเชื่อมต่อ SQLite งงหนัก
const sqlite3 = require('sqlite3').verbose();
const dbPath = path.resolve(__dirname, 'notifications.db');

const sqliteDb = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('เกิดข้อผิดพลาดในการเชื่อมต่อกับฐานข้อมูล SQLite:', err);
    } else {
        console.log('เชื่อมต่อกับฐานข้อมูล SQLite เรียบร้อยแล้ว');
    }
});

// ตรวจสอบและสร้างตารางหากไม่มี
sqliteDb.serialize(() => {
    sqliteDb.run(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_profile_image TEXT,
        user_name TEXT,
        message TEXT,
        user_id INTEGER,
        status TEXT
    )`);

    sqliteDb.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT,
        user_profile_image TEXT
    )`);
});

// เส้นทางสำหรับยืนยันการแลกเปลี่ยน
app.post('/confirm-exchange', async (req, res) => {
    const user_profile_image = req.body.user_profile_image || '/images/default-profile.png';
    const user_name = req.body.user_name || 'Unknown';
    const message = req.body.message || 'No message';
    const user_id = req.body.user_id !== undefined ? req.body.user_id : null;

    // ตรวจสอบข้อมูลที่สำคัญ
    if (user_name === undefined || user_id === undefined) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    // คำสั่ง SQL และพารามิเตอร์
    const sql = 'INSERT INTO notifications (user_profile_image, user_name, message, user_id) VALUES (?, ?, ?, ?)';
    const params = [user_profile_image, user_name, message, user_id];

    try {
        // ดำเนินการคำสั่ง SQL
        const [result] = await dbConnection.execute(sql, params);
        console.log('Notification saved successfully:', result);

        // ส่งการแจ้งเตือนไปยังผู้ใช้
        io.emit('exchange-confirmed', { user_name, user_id });
        return res.json({ message: 'Exchange confirmed' });
    } catch (err) {
        console.error('Error saving notification:', err.message);
        return res.status(500).json({ error: 'Failed to save notification' });
    }
});



// เส้นทางสำหรับยอมรับการแจ้งเตือน
app.post('/accept-notification', (req, res) => {
    const notificationId = req.body.id;

    if (notificationId === undefined) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    dbConnection.execute("UPDATE notifications SET status = 'ได้รับการแลกเปลี่ยนแล้ว' WHERE id = ?", [notificationId])
        .then(() => {
            console.log(`การแจ้งเตือน ID ${notificationId} ถูกอัพเดตสถานะเรียบร้อยแล้ว`);
            res.send('การแจ้งเตือนถูกอัพเดตสถานะเรียบร้อยแล้ว');
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน:', err);
            res.status(500).send('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน');
        });
});

app.post('/reject-notification', (req, res) => {
    const { id } = req.body;

    if (id === undefined) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    dbConnection.execute(`DELETE FROM notifications WHERE id = ?`, [id])
        .then(() => {
            res.json({ message: 'การแจ้งเตือนถูกปฏิเสธแล้ว' });
        })
        .catch(err => {
            console.error('Error rejecting notification:', err.message);
            res.status(500).json({ message: 'เกิดข้อผิดพลาดในการปฏิเสธการแจ้งเตือน' });
        });
});


// เส้นทางสำหรับปฏิเสธการแจ้งเตือน
app.post('/reject-notification', (req, res) => {
    const { id } = req.body;
    const sql = `DELETE FROM notifications WHERE id = ?`;

    sqliteDb.run(sql, [id], function(err) {
        if (err) {
            console.error('Error rejecting notification:', err.message);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการปฏิเสธการแจ้งเตือน' });
        }
        res.json({ message: 'การแจ้งเตือนถูกปฏิเสธแล้ว' });
    });
});

// เส้นทางสำหรับแสดงหน้าการแจ้งเตือน
app.get('/notifications', (req, res) => {
    const sql = `SELECT notifications.*, users.user_profile_image, users.user_name
                FROM notifications
                JOIN users ON notifications.user_id = users.id`;

    sqliteDb.all(sql, [], (err, rows) => {
        if (err) {
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลการแจ้งเตือน:', err);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลการแจ้งเตือน' });
        }
        console.log('ข้อมูลการแจ้งเตือน:', rows); // เพิ่ม log เพื่อตรวจสอบข้อมูล
        res.render('notifications', {
            name: req.session.userName,
            notifications: rows
        });
    });
});


















// เส้นทางสำหรับดูรายละเอียดผู้ใช้และสินค้า
app.get('/view-user/:user_id', ifNotLoggedIn, function (req, res) {
    const userId = req.params.user_id;

    const userQuery = 'SELECT * FROM users WHERE id = ?';
    const productsQuery = 'SELECT * FROM products WHERE user_id = ?';
    const settingsQuery = 'SELECT * FROM settinguser WHERE user_id = ?';

    dbConnection.execute(userQuery, [userId])
        .then(([userRows]) => {
            if (userRows.length > 0) {
                const user = userRows[0];

                return Promise.all([
                    dbConnection.execute(productsQuery, [user.id]),
                    dbConnection.execute(settingsQuery, [user.id])
                ]).then(([productResults, settingsResults]) => {
                    const products = productResults[0];
                    const settings = settingsResults[0];

                    // เพิ่ม products ลงใน user object
                    user.products = products;

                    // เรนเดอร์หน้า view-user พร้อมส่ง user และ settings
                    res.render('view-user', {
                        user: user,
                        settings: settings
                    });
                });
            } else {
                res.status(404).send('ไม่พบผู้ใช้');
            }
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('เกิดข้อผิดพลาดขณะดึงข้อมูลผู้ใช้');
        });
});



app.get('/edit-product/:product_id', ifNotLoggedIn, function (req, res) {
    const productId = req.params.product_id;
    const query = 'SELECT * FROM products WHERE id = ?';

    dbConnection.execute(query, [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const product = rows[0];
                // ตรวจสอบว่าผู้ใช้เป็นเจ้าของสินค้าหรือไม่
                if (product.user_id !== req.session.userID) {
                    return res.status(403).send(`
                        <html>
                        <head>
                            <style>
                                body {
                                    display: flex;
                                    flex-direction: column;
                                    align-items: center;
                                    justify-content: center;
                                    height: 100vh;
                                    margin: 0;
                                }
                                .error-message {
                                    font-size: 24px;
                                    color: red;
                                    font-weight: bold;
                                    text-align: center;
                                    margin-bottom: 20px;
                                }
                                .back-button {
                                    display: block;
                                    width: 200px;
                                    padding: 10px;
                                    font-size: 18px;
                                    text-align: center;
                                    color: white;
                                    background-color: blue;
                                    border: none;
                                    border-radius: 5px;
                                    cursor: pointer;
                                }
                                .back-button:hover {
                                    background-color: darkblue;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="error-message">คุณไม่มีสิทธิ์ในการแก้ไขผลิตภัณฑ์นี้</div>
                            <button class="back-button" onclick="window.location.href='/'">กลับไปหน้า Home</button>
                        </body>
                        </html>
                    `);
                }
                return res.render('edit-product', { product });
            } else {
                return res.status(404).send('ไม่พบผลิตภัณฑ์');
            }
        })
        .catch(err => {
            console.error(err);
            return res.status(500).send('เกิดข้อผิดพลาดขณะดึงข้อมูลผลิตภัณฑ์');
        });
});



// เส้นทางสำหรับแก้ไขสินค้า (POST)


// เส้นทางสำหรับแก้ไขสินค้า (POST)
app.post('/edit-product/:product_id', ifNotLoggedIn, upload.single('image'), function (req, res) {
    const productId = req.params.product_id;
    const { name, description, location, status } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : req.body.image_url; // ใช้รูปภาพใหม่ถ้ามีการอัปโหลด

    console.log('Image file:', req.file); // เพิ่มดีบั๊ก
    console.log('Image URL:', req.body.image_url); // เพิ่มดีบั๊ก

    const selectQuery = 'SELECT * FROM products WHERE id = ?';
    const updateQuery = 'UPDATE products SET name = ?, description = ?, location = ?, status = ?, image = ? WHERE id = ?';

    dbConnection.execute(selectQuery, [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const product = rows[0];
                if (product.user_id !== req.session.userID) {
                    return res.status(403).send('คุณไม่มีสิทธิ์ในการแก้ไขผลิตภัณฑ์นี้');
                }
                // แก้ไขสินค้า โดยตรวจสอบค่า undefined และกำหนดเป็น null ถ้าจำเป็น
                const updatedName = name || null;
                const updatedDescription = description || null;
                const updatedLocation = location || null;
                const updatedStatus = status || null;
                const updatedImage = image || null;

                return dbConnection.execute(updateQuery, [updatedName, updatedDescription, updatedLocation, updatedStatus, updatedImage, productId]);
            } else {
                return res.status(404).send('ไม่พบผลิตภัณฑ์');
            }
        })
        .then(() => {
            res.redirect('/view-user/' + req.session.userID); // เปลี่ยนเส้นทางหลังจากแก้ไขสำเร็จ
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('เกิดข้อผิดพลาดขณะอัปเดตผลิตภัณฑ์');
        });
});






// เส้นทางสำหรับลบสินค้า (POST)
app.post('/delete-product/:product_id', ifNotLoggedIn, function (req, res) {
    const productId = req.params.product_id;
    
    const selectQuery = 'SELECT * FROM products WHERE id = ?';
    const deleteQuery = 'DELETE FROM products WHERE id = ?';

    dbConnection.execute(selectQuery, [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const product = rows[0];
                if (product.user_id !== req.session.userID) {
                    return res.status(403).send(`
                        <html>
                        <head>
                            <style>
                                body {
                                    display: flex;
                                    flex-direction: column;
                                    align-items: center;
                                    justify-content: center;
                                    height: 100vh;
                                    margin: 0;
                                }
                                .error-message {
                                    font-size: 24px;
                                    color: red;
                                    font-weight: bold;
                                    text-align: center;
                                    margin-bottom: 20px;
                                }
                                .back-button {
                                    display: block;
                                    width: 200px;
                                    padding: 10px;
                                    font-size: 18px;
                                    text-align: center;
                                    color: white;
                                    background-color: blue;
                                    border: none;
                                    border-radius: 5px;
                                    cursor: pointer;
                                }
                                .back-button:hover {
                                    background-color: darkblue;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="error-message">คุณไม่มีสิทธิ์ในการลบผลิตภัณฑ์นี้</div>
                            <button class="back-button" onclick="window.location.href='/'">กลับไปหน้า Home</button>
                        </body>
                        </html>
                    `);
                }
                return dbConnection.execute(deleteQuery, [productId]);
            } else {
                return res.status(404).send(`
                    <html>
                    <head>
                        <style>
                            body {
                                display: flex;
                                flex-direction: column;
                                align-items: center;
                                justify-content: center;
                                height: 100vh;
                                margin: 0;
                            }
                            .error-message {
                                font-size: 24px;
                                color: red;
                                font-weight: bold;
                                text-align: center;
                                margin-bottom: 20px;
                            }
                            .back-button {
                                display: block;
                                width: 200px;
                                padding: 10px;
                                font-size: 18px;
                                text-align: center;
                                color: white;
                                background-color: blue;
                                border: none;
                                border-radius: 5px;
                                cursor: pointer;
                            }
                            .back-button:hover {
                                background-color: darkblue;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="error-message">ไม่พบผลิตภัณฑ์</div>
                        <button class="back-button" onclick="window.location.href='/'">กลับไปหน้า Home</button>
                    </body>
                    </html>
                `);
            }
        })
        .then(() => {
            // Redirect หลังจากลบเสร็จ
            res.redirect('/view-user/' + req.session.userID);
        })
        .catch(err => {
            console.error(err);
            // ตรวจสอบว่าไม่ได้ส่งคำตอบมากกว่าหนึ่งครั้ง
            if (!res.headersSent) {
                res.status(500).send(`
                    <html>
                    <head>
                        <style>
                            body {
                                display: flex;
                                flex-direction: column;
                                align-items: center;
                                justify-content: center;
                                height: 100vh;
                                margin: 0;
                            }
                            .error-message {
                                font-size: 24px;
                                color: red;
                                font-weight: bold;
                                text-align: center;
                                margin-bottom: 20px;
                            }
                            .back-button {
                                display: block;
                                width: 200px;
                                padding: 10px;
                                font-size: 18px;
                                text-align: center;
                                color: white;
                                background-color: blue;
                                border: none;
                                border-radius: 5px;
                                cursor: pointer;
                            }
                            .back-button:hover {
                                background-color: darkblue;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="error-message">เกิดข้อผิดพลาดขณะลบผลิตภัณฑ์</div>
                        <button class="back-button" onclick="window.location.href='/'">กลับไปหน้า Home</button>
                    </body>
                    </html>
                `);
            }
        });
});








// Search products

app.get('/search', ifNotLoggedIn, (req, res) => {
    const query = req.query.query; // รับค่าค้นหาจากพารามิเตอร์ query ที่ผู้ใช้กรอกในฟอร์ม
    const status = req.query.status; // รับค่าสถานะ (free หรือ exchange) จากปุ่มกรองที่ผู้ใช้เลือก

    // เริ่มต้น SQL query เพื่อค้นหาสินค้า
    let sql = "SELECT products.*, users.name AS user_name FROM products JOIN users ON products.user_id = users.id WHERE (products.name LIKE ? OR products.description LIKE ?)";
     // ตั้งค่าพารามิเตอร์สำหรับ SQL query
    let params = [`%${query}%`, `%${query}%`];


    // ถ้ามีพารามิเตอร์ status ถูกส่งมาด้วย ให้เพิ่มเงื่อนไขใน SQL query 
    if (status) {
        sql += " AND products.status = ?";
        params.push(status); // เพิ่มค่าสถานะลงในพารามิเตอร์ของ query
    }
    
    // ดำเนินการ query ไปที่ฐานข้อมูล
    dbConnection.execute(sql, params).then(([rows]) => {
         // เมื่อ query เสร็จสิ้น ให้ render หน้า home พร้อมกับผลลัพธ์ของสินค้า
        res.render('home', {
            name: req.session.userName,  // ส่งชื่่อผู้ใช้ไปยัง template
            products: rows   // ส่งผลลัพธ์ของสินค้าไปยัง template
        });
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while searching for products.');
    });
});









io.on('connection', (socket) => {
    console.log('A user connected');
    const userName = socket.handshake.query.userName;

    if (!userName) {
        console.error('User name is not provided');
        socket.disconnect();
        return;
    }

    // ส่งประวัติแชทสำหรับผู้ใช้ที่เชื่อมต่อ
    dbConnection.execute(
        'SELECT DISTINCT product_user FROM chat_messages WHERE user_name = ? UNION SELECT DISTINCT user_name FROM chat_messages WHERE product_user = ?',
        [userName, userName]
    ).then(([rows]) => {
        socket.emit('chat partners', rows);
    }).catch(err => {
        console.error(err);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });

    socket.on('chat message', (msg) => {
        const userID = msg.userID;

        if (!userID || !userName || !msg.message || !msg.productUser) {
            console.error('One or more parameters are missing or undefined for chat message');
            return;
        }

        const messageData = {
            user_id: userID,
            user_name: userName,
            message: msg.message,
            product_user: msg.productUser,
            timestamp: new Date(),
            time: new Date().toLocaleTimeString()
        };

        dbConnection.execute(
            'INSERT INTO chat_messages (user_id, user_name, message, product_user, timestamp) VALUES (?, ?, ?, ?, ?)',
            [messageData.user_id, messageData.user_name, messageData.message, messageData.product_user, messageData.timestamp]
        ).then(() => {
            io.emit('chat message', messageData);
            io.to(userName).emit('update chat partners', { user_name: messageData.user_name, product_user: messageData.product_user });
            io.to(messageData.product_user).emit('update chat partners', { user_name: messageData.user_name, product_user: messageData.product_user });

            // ส่งประวัติแชทให้ผู้รับเมื่อได้รับข้อความ
            io.to(messageData.product_user).emit('chat history', [messageData]);
        }).catch(err => {
            console.error(err);
        });
    });

    socket.on('chat image', (msg) => {
        const userID = msg.userID;

        if (!userID || !userName || !msg.imageUrl || !msg.productUser) {
            console.error('One or more parameters are missing or undefined for chat image');
            return;
        }

        const imageData = {
            user_id: userID,
            user_name: userName,
            image_url: msg.imageUrl || null,
            product_user: msg.productUser,
            timestamp: new Date(),
            time: new Date().toLocaleTimeString()
        };

        dbConnection.execute(
            'INSERT INTO chat_messages (user_id, user_name, product_user, timestamp, image_url) VALUES (?, ?, ?, ?, ?)',
            [imageData.user_id, imageData.user_name, imageData.product_user, imageData.timestamp, imageData.image_url]
        ).then(() => {
            io.emit('chat image', imageData);
            io.to(userName).emit('update chat partners', { user_name: imageData.user_name, product_user: imageData.product_user });
            io.to(imageData.product_user).emit('update chat partners', { user_name: imageData.user_name, product_user: imageData.product_user });

            // ส่งประวัติแชทให้ผู้รับเมื่อได้รับรูปภาพ
            io.to(imageData.product_user).emit('chat history', [imageData]);
        }).catch(err => {
            console.error(err);
        });
    });
});




app.get('/chat-history/:userName/:productUser', (req, res) => {
    const { userName, productUser } = req.params;
    dbConnection.execute(
        'SELECT * FROM chat_messages WHERE (user_name = ? AND product_user = ?) OR (user_name = ? AND product_user = ?) ORDER BY timestamp ASC',
        [userName, productUser, productUser, userName]
    ).then(([rows]) => {
        res.json(rows);
    }).catch(err => {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch chat history' });
    });
});







// Get chat history and render the save-offer page
app.get('/save-offer', ifNotLoggedIn, (req, res) => {
    dbConnection.execute(
        'SELECT * FROM chat_messages WHERE user_id = ? ORDER BY timestamp ASC',
        [req.session.userID]
    ).then(([rows]) => {
        res.render('save-offer', {
            name: req.session.userName,
            userID: req.session.userID,
            messages: rows
        });
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while fetching chat history.');
    });
});

// Get chat history for specific user and product user
app.get('/chat-history/:productUser', ifNotLoggedIn, (req, res) => {
    const productUser = req.params.productUser;
    dbConnection.execute(
        'SELECT * FROM chat_messages WHERE (user_name = ? AND product_user = ?) OR (user_name = ? AND product_user = ?) ORDER BY timestamp ASC',
        [req.session.userName, productUser, productUser, req.session.userName]
    ).then(([rows]) => {
        const messages = rows.map(row => ({
            ...row,
            time: new Date(row.timestamp).toLocaleString()
        }));
        res.json(messages);
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while fetching chat history.');
    });
});

app.get('/chat-partners', ifNotLoggedIn, (req, res) => {
    dbConnection.execute(
        'SELECT DISTINCT product_user FROM chat_messages WHERE user_name = ?',
        [req.session.userName]
    ).then(([rows]) => {
        res.json(rows);
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while fetching chat partners.');
    });
});

app.post('/upload-image', upload.single('image'), (req, res) => {
    const tempPath = req.file.path;
    const targetPath = path.join(__dirname, 'public/uploads/', `${Date.now()}-${req.file.originalname}`);

    fs.rename(tempPath, targetPath, err => {
        if (err) return res.status(500).json({ success: false, error: err });

        const imageUrl = `/uploads/${path.basename(targetPath)}`;
        res.json({ success: true, url: imageUrl });
    });
});



app.post('/save-image-message', (req, res) => {
    const { imageUrl, userID, productUser } = req.body;
    const timestamp = new Date().toLocaleTimeString();

    dbConnection.execute(
        'INSERT INTO chat_messages (user_id, user_name, product_user, timestamp, image) VALUES (?, ?, ?, ?, ?)',
        [userID, userName, productUser, new Date(), imageUrl]
    ).then(result => {
        res.json({ success: true });
    }).catch(err => {
        res.status(500).json({ success: false, error: err });
    });
});






// สร้างตัวแปร chatHistory เพื่อเก็บประวัติแชท
let chatHistory = {};

io.on('connection', function (socket) {
    socket.on('chat message', function (msg) {
        const userA = msg.name; // ชื่อผู้ใช้ที่ส่งข้อความ
        const userB = msg.productUser; // ผู้ใช้ที่ถูกส่งถึง
        const timestamp = new Date().toLocaleString(); // เวลาของข้อความ

        // ตรวจสอบว่าเป็นการสนทนาระหว่าง userA กับ userB หรือ userB กับ userA
        if (!chatHistory[userA]) {
            chatHistory[userA] = {};
        }
        if (!chatHistory[userB]) {
            chatHistory[userB] = {};
        }

        // เพิ่มข้อความลงในประวัติแชทของทั้งสองฝ่าย
        if (!chatHistory[userA][userB]) {
            chatHistory[userA][userB] = [];
        }
        if (!chatHistory[userB][userA]) {
            chatHistory[userB][userA] = [];
        }

        chatHistory[userA][userB].push({ message: msg.message, timestamp: timestamp });
        chatHistory[userB][userA].push({ message: msg.message, timestamp: timestamp });

        // ส่งข้อความกลับไปยังทุกคนในห้องแชท
        io.emit('chat message', msg);
    });
});

//การแจ้งเตือน





// Start server
server.listen(3000, () => console.log("Server is running..."));
