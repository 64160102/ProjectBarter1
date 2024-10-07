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

const isAdmin = (req, res, next) => {
    const userId = req.session.userID;
    dbConnection.execute('SELECT r.role FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?', [userId])
        .then(([rows]) => {
            if (rows.length > 0 && rows[0].role === 'admin') {
                next();
            } else {
                res.status(403).send('Access denied.');
            }
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('An error occurred while checking admin privileges.');
        });
};

app.get('/admin', ifNotLoggedIn, isAdmin, (req, res) => {
    res.render('admin', {
        name: req.session.userName
    });
});

// Route for fetching dashboard data
app.get('/admin/dashboard-data', ifNotLoggedIn, isAdmin, async (req, res) => {
    try {
        // Query to get total number of users
        const [totalUsersRows] = await dbConnection.execute('SELECT COUNT(*) as totalUsers FROM users');
        const totalUsers = totalUsersRows[0].totalUsers;

        // Query to get total number of exchanged items
        const [totalExchangedItemsRows] = await dbConnection.execute('SELECT COUNT(*) as totalExchangedItems FROM products WHERE status = "exchange"');
        const totalExchangedItems = totalExchangedItemsRows[0].totalExchangedItems;

        // Query to get total number of free items
        const [totalFreeItemsRows] = await dbConnection.execute('SELECT COUNT(*) as totalFreeItems FROM products WHERE status = "free"');
        const totalFreeItems = totalFreeItemsRows[0].totalFreeItems;

        // Query to get the latest notifications
        const [latestNotificationsRows] = await dbConnection.execute('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 5');
        const latestNotifications = latestNotificationsRows.map(row => ({ message: row.message }));

        res.json({
            totalUsers,
            totalExchangedItems,
            totalFreeItems,
            latestNotifications
        });
    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).json({ error: 'Error fetching dashboard data' });
    }
});

// เส้นทางสำหรับดูรายการสินค้า
app.get('/admin/items', ifNotLoggedIn, isAdmin, (req, res) => {
    dbConnection.execute('SELECT * FROM products')
        .then(([rows]) => {
            res.render('items', {
                user: {
                    name: req.session.userName,
                    products: rows
                }
            });
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('An error occurred while fetching items.');
        });
});

app.get('/admin/a-upload', ifNotLoggedIn, (req, res) => {
    res.render('a-upload', {
        name: req.session.userName
    });
});

app.post('/a-upload', ifNotLoggedIn, upload.single('product_image'), (req, res) => {
    if (!req.file) {
        return res.render('a-upload', {
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
        res.redirect('/admin/items');
    }).catch(err => {
        console.error(err);
        res.send('Error occurred while uploading the product.');
    });
});

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
    const { user_email, user_pass } = req.body;
    if (validation_result.isEmpty()) {
        dbConnection.execute('SELECT * FROM users WHERE email=?', [user_email])
            .then(([rows]) => {
                if (rows.length === 1) {
                    const user = rows[0];

                    // ตรวจสอบสถานะการแบน
                    if (user.banned) {
                        return res.render('login-register', {
                            login_errors: ['Your account has been banned. Please contact support.']
                        });
                    }

                    bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                        if (compare_result === true) {
                            req.session.isLoggedIn = true;
                            req.session.userID = rows[0].id;
                            req.session.userName = rows[0].name;

                            // Check the role of the user
                            dbConnection.execute('SELECT r.role FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?', [rows[0].id])
                                .then(([roleRows]) => {
                                    if (roleRows.length > 0) {
                                        req.session.userRole = roleRows[0].role;
                                        if (roleRows[0].role === 'admin') {
                                            return res.redirect('/admin');
                                        } else {
                                            return res.redirect('/');
                                        }
                                    } else {
                                        req.session.userRole = 'user'; // If no role found, set to user
                                        return res.redirect('/');
                                    }
                                })
                                .catch(err => {
                                    console.error(err);
                                    res.status(500).send('An error occurred while checking user role.');
                                });
                        } else {
                            res.render('login-register', {
                                login_errors: ['Invalid Password']
                            });
                        }
                    }).catch(err => {
                        if (err) throw err;
                    });
                } else {
                    res.render('login-register', {
                        login_errors: ['Invalid Email Address']
                    });
                }
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









// เส้นทางสำหรับยืนยันการแลกเปลี่ยน
app.post('/confirm-exchange', (req, res) => {
    const { user_name, user_id, user_profile_image } = req.body; 
    console.log('คำร้องแลกเปลี่ยนที่ได้รับ:', req.body);

    // ตรวจสอบข้อมูล
    if (!user_name || !user_id || !user_profile_image) {
        return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
    }

    // ดึงข้อมูลจาก session
    const senderProfileImage = req.session.profile_image || '/images/default-profile.png';
    const senderName = req.session.userName;
    const senderId = req.session.userID;

    // ตรวจสอบว่าผู้ส่งและผู้รับไม่ใช่คนเดียวกัน
    if (senderId === user_id) {
        return res.status(400).json({ message: 'ไม่สามารถส่งคำร้องไปยังตัวเองได้' });
    }

    // SQL ในการเพิ่มการแจ้งเตือนใหม่
    const sql = `INSERT INTO notifications (sender_profile_image, sender_name, user_profile_image, user_name, message, status, sender_id, receiver_id, created_at)
                 VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NOW())`;

    // ข้อมูลที่จะถูกใช้ใน query
    const params = [senderProfileImage, senderName, user_profile_image, user_name, 'ต้องการสินค้าของคุณ', senderId, user_id];

    // query ไปยัง MySQL
    dbConnection.query(sql, params, (err, result) => {
        if (err) {
            console.error('เกิดข้อผิดพลาดในการยืนยันการแลกเปลี่ยน:', err.message);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการยืนยันการแลกเปลี่ยน' });
        }

        // ส่งผลลัพธ์กลับ
        res.json({ message: 'ยืนยันการแลกเปลี่ยนสำเร็จ', id: result.insertId });
    });
});

// เส้นทางสำหรับยอมรับการแจ้งเตือน
app.post('/accept-notification', (req, res) => {
    const notificationId = req.body.id;
    console.log('Received notificationId:', notificationId);

    // SQL สำหรับอัพเดตสถานะเป็น 'accepted'
    const sql = "UPDATE notifications SET status = 'accepted', updated_at = NOW() WHERE id = ?";

    dbConnection.query(sql, [notificationId], (err, result) => {
        if (err) {
            console.error('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน:', err);
            return res.status(500).send('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน');
        }
        res.send('การแจ้งเตือนถูกอัพเดตสถานะเรียบร้อยแล้ว');
    });
});

// เส้นทางสำหรับปฏิเสธการแจ้งเตือน
app.post('/reject-notification', (req, res) => {
    const { id } = req.body;

    // SQL สำหรับอัพเดตสถานะเป็น 'rejected'
    const sql = `UPDATE notifications SET status = 'rejected', updated_at = NOW() WHERE id = ?`;

    dbConnection.query(sql, [id], function(err, result) {
        if (err) {
            console.error('Error rejecting notification:', err.message);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการปฏิเสธการแจ้งเตือน' });
        }
        res.json({ message: 'การแจ้งเตือนถูกปฏิเสธแล้ว' });
    });
});


// เส้นทางสำหรับแสดงหน้าการแจ้งเตือน
app.get('/notifications', (req, res) => {
    const currentUserId = req.session.userID;
    const senderName = req.session.userName;

    if (!currentUserId) {
        return res.status(401).send('Please log in to view your notifications.');
    }

    const notificationsQuery = `SELECT * FROM notifications WHERE receiver_id = ?`;

    // ใช้ Promise ในการจัดการการดึงข้อมูล
    dbConnection.execute(notificationsQuery, [currentUserId])
        .then(([notificationRows]) => {
            if (notificationRows.length > 0) {
                // เรนเดอร์หน้า notifications พร้อมส่งข้อมูลการแจ้งเตือน
                res.render('notifications', {
                    name: req.session.userName,
                    notifications: notificationRows,
                    userID: req.session.userID,
                    profile_image: req.session.profile_image
                });
            } else {
                // ถ้าไม่มีการแจ้งเตือน
                res.render('notifications', {
                    name: req.session.userName,
                    notifications: [],
                    userID: req.session.userID
                });
            }
        })
        .catch(err => {
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลการแจ้งเตือน:', err);
            res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลการแจ้งเตือน' });
        });
});

// เส้นทางสำหรับแสดงหน้าโปรไฟล์ผู้ใช้
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = `SELECT * FROM users WHERE id = ?`;

    console.log('เข้าสู่เส้นทาง /user/:id');
    console.log('User ID:', userId);

    // ใช้ execute() แทน query() เพื่อรองรับการใช้ Promise
    dbConnection.execute(sql, [userId])
        .then(([results]) => {
            // ตรวจสอบว่าพบข้อมูลผู้ใช้หรือไม่
            if (results.length === 0) {
                console.log('ไม่พบผู้ใช้สำหรับ ID:', userId);
                return res.status(404).send('ไม่พบผู้ใช้');
            }

            // ส่งข้อมูลผู้ใช้ไปยัง EJS
            const user = results[0]; // ดึงผู้ใช้จากผลลัพธ์
            console.log('พบข้อมูลผู้ใช้:', user);

            // เรนเดอร์หน้า user พร้อมส่งข้อมูลผู้ใช้ไปยัง EJS
            res.render('user', { 
                name: req.session.userName,
                user: user
            });
        })
        .catch(err => {
            // จัดการข้อผิดพลาดในกรณีที่เกิดปัญหาในการดึงข้อมูลจากฐานข้อมูล
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', err);
            res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้' });
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



// Route สำหรับแอดมินแก้ไขผลิตภัณฑ์
app.get('/edit-product/:product_id', ifNotLoggedIn, function (req, res) {
    const productId = req.params.product_id;
    const query = 'SELECT * FROM products WHERE id = ?';

    dbConnection.execute(query, [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const product = rows[0];
                // ตรวจสอบ role ของผู้ใช้
                if (req.session.userRole !== 'admin' && product.user_id !== req.session.userID) {
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
                if (req.session.userRole !== 'admin' && product.user_id !== req.session.userID) {
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
            if (req.session.userRole !== 'admin') {
                res.redirect('/view-user/' + req.session.userID); // เปลี่ยนเส้นทางไปยังหน้าดูข้อมูลผู้ใช้
            } else {
                res.redirect('/admin/items'); // เปลี่ยนเส้นทางไปยังหน้ารายการสินค้าสำหรับแอดมิน
            }
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
                if (req.session.userRole !== 'admin' && product.user_id !== req.session.userID) {
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
            if (req.session.userRole !== 'admin') {
                res.redirect('/view-user/' + req.session.userID); // เปลี่ยนเส้นทางไปยังหน้าดูข้อมูลผู้ใช้
            } else {
                res.redirect('/admin/items'); // เปลี่ยนเส้นทางไปยังหน้ารายการสินค้าสำหรับแอดมิน
            }
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
    const query = req.query.query;
    const status = req.query.status;

    let sql = "SELECT products.*, users.name AS user_name FROM products JOIN users ON products.user_id = users.id WHERE (products.name LIKE ? OR products.description LIKE ?)";
    let params = [`%${query}%`, `%${query}%`];

    if (status) {
        sql += " AND products.status = ?";
        params.push(status);
    }

    dbConnection.execute(sql, params).then(([rows]) => {
        const userRole = req.session.userRole;

        res.render('home', {
            name: req.session.userName, // ส่งชื่อผู้ใช้ไปยัง template
            products: rows, // ส่งผลลัพธ์ของสินค้าไปยัง template
            sessionUserName: req.session.userName,  // ส่งค่า session userName
            sessionUserID: req.session.userID,      // ส่งค่า session userID
            sessionProfileImage: req.session.profile_image // ส่งค่า session profile_image
        });
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while searching for products.');
    });
});



// เส้นทางค้นหาสินค้าสำหรับ admin
app.get('/admin/search', ifNotLoggedIn, isAdmin, (req, res) => {
    const query = req.query.query;
    const status = req.query.status;

    let sql = "SELECT products.*, users.name AS user_name FROM products JOIN users ON products.user_id = users.id WHERE (products.name LIKE ? OR products.description LIKE ?)";
    let params = [`%${query}%`, `%${query}%`];

    if (status) {
        sql += " AND products.status = ?";
        params.push(status);
    }

    dbConnection.execute(sql, params).then(([rows]) => {
        res.render('items', {
            user: {
                name: req.session.userName,
                products: rows
            },
            sessionUserName: req.session.userName,  // ส่งค่า session userName
            sessionUserID: req.session.userID,      // ส่งค่า session userID
            sessionProfileImage: req.session.profile_image // ส่งค่า session profile_image
        });
    }).catch(err => {
        console.error(err);
        res.status(500).send('Error occurred while searching for products.');
    });
});



// เส้นทางเพื่อแสดงหน้าการจัดการผู้ใช้
app.get('/admin/users', ifNotLoggedIn, isAdmin, (req, res) => {
    dbConnection.execute('SELECT users.*, roles.role FROM users LEFT JOIN user_roles ON users.id = user_roles.user_id LEFT JOIN roles ON user_roles.role_id = roles.id')
        .then(([rows]) => {
            res.render('users', {
                users: rows,
                name: req.session.userName
            });
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('เกิดข้อผิดพลาดขณะดึงข้อมูลผู้ใช้');
        });
});

// ฟังก์ชันสำหรับอัปเดตบทบาทของผู้ใช้
function updateUserRole(userId, newRoleId) {
    dbConnection.execute('SELECT role_id FROM user_roles WHERE user_id = ?', [userId])
        .then(([rows]) => {
            if (rows.length > 0 && rows[0].role_id === newRoleId) {
                console.log('บทบาทที่ต้องการอัปเดตเป็นบทบาทเดิม');
                return Promise.resolve(); // ไม่จำเป็นต้องทำอะไรเพิ่มเติม
            } else {
                return dbConnection.execute('DELETE FROM user_roles WHERE user_id = ?', [userId])
                    .then(() => {
                        return dbConnection.execute('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', [userId, newRoleId]);
                    });
            }
        })
        .then(() => {
            console.log('User role updated successfully.');
        })
        .catch(err => {
            console.error('Error updating user role:', err);
        });
}

// เส้นทางเพื่ออัปเดตบทบาทของผู้ใช้
app.post('/admin/users/:userId/role', ifNotLoggedIn, isAdmin, (req, res) => {
    const userId = req.params.userId;
    const newRole = req.body.role;
    
    dbConnection.execute('SELECT id FROM roles WHERE role = ?', [newRole])
        .then(([rows]) => {
            if (rows.length > 0) {
                const roleId = rows[0].id;
                return updateUserRole(userId, roleId);
            } else {
                throw new Error('Role not found');
            }
        })
        .then(() => {
            res.redirect('/admin/users');
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('เกิดข้อผิดพลาดขณะอัปเดตบทบาทผู้ใช้');
        });
});

// เส้นทางเพื่อแบนหรือยกเลิกการแบนผู้ใช้
app.post('/admin/users/:userId/ban', ifNotLoggedIn, isAdmin, (req, res) => {
    const userId = req.params.userId;
    
    dbConnection.execute('SELECT banned FROM users WHERE id = ?', [userId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const newStatus = !rows[0].banned; // Toggle ban status
                return dbConnection.execute('UPDATE users SET banned = ? WHERE id = ?', [newStatus, userId]);
            } else {
                throw new Error('User not found');
            }
        })
        .then(() => {
            res.redirect('/admin/users');
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('เกิดข้อผิดพลาดขณะอัปเดตสถานะผู้ใช้');
        });
});

function sendNotification(senderId, receiverId, message) {
    const status = 'pending'; // สถานะเริ่มต้น
    dbConnection.execute('INSERT INTO notifications (sender_id, receiver_id, message, status) VALUES (?, ?, ?, ?)', 
    [senderId, receiverId, message, status])
    .then(() => {
        console.log('Notification sent successfully.');
    })
    .catch(err => {
        console.error('Error sending notification:', err);
    });
}

function updateNotificationStatus(notificationId, newStatus) {
    dbConnection.execute('UPDATE notifications SET status = ? WHERE id = ?', [newStatus, notificationId])
    .then(() => {
        console.log('Notification status updated successfully.');
    })
    .catch(err => {
        console.error('Error updating notification status:', err);
    });
}

app.get('/admin/a-notifications', ifNotLoggedIn, (req, res) => {
    const userId = req.session.userID || null;

    if (!userId) {
        console.error('User ID is undefined.');
        return res.status(400).send('User ID is undefined.');
    }

    dbConnection.execute('SELECT * FROM notifications WHERE receiver_id = ? ORDER BY created_at DESC', [userId])
        .then(([rows]) => {
            res.render('notifications', {
                notifications: rows
            });
        })
        .catch(err => {
            console.error('Error retrieving notifications:', err);
            res.status(500).send('Error occurred while retrieving notifications.');
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
