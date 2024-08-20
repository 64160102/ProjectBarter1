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

// ตั้งค่าการใช้งาน body-parser เพื่อให้สามารถรับข้อมูลจากฟอร์มได้
app.use(express.urlencoded({ extended: true }));


// ตั้งค่า session
app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'], // คีย์สำหรับเข้ารหัสคุกกี้ session
    maxAge: 24 * 60 * 60 * 1000 // อายุของ session ใน millisecond (ในที่นี้คือ 1 วัน)
}));

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



  

const sqlite3 = require('sqlite3').verbose();
// กำหนด dbPath ให้ชี้ไปยังตำแหน่งที่ตั้งของไฟล์ฐานข้อมูล SQLite
const dbPath = path.resolve(__dirname, 'notifications');

// เชื่อมต่อกับฐานข้อมูล
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('เกิดข้อผิดพลาดในการเชื่อมต่อกับฐานข้อมูล:', err);
  } else {
    console.log('เชื่อมต่อกับฐานข้อมูลเรียบร้อยแล้ว');
  }
});
/*
// ตรวจสอบคอลัมน์ในตาราง notifications
db.all("PRAGMA table_info(notifications)", (err, columns) => {
  if (err) {
    console.error('เกิดข้อผิดพลาดในการตรวจสอบคอลัมน์:', err);
    return;
  }

  // ตรวจสอบว่ามีคอลัมน์ user_id หรือไม่
  const hasUserIdColumn = columns.some(column => column.name === 'user_id');
  // ตรวจสอบว่ามีคอลัมน์ status หรือไม่
  const hasStatusColumn = columns.some(column => column.name === 'status');

  // เพิ่มคอลัมน์ user_id หากยังไม่มี
  if (!hasUserIdColumn) {
    db.run("ALTER TABLE notifications ADD COLUMN user_id INTEGER", (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการเพิ่มคอลัมน์ user_id:', err);
      } else {
        console.log('เพิ่มคอลัมน์ user_id เรียบร้อยแล้ว');
      }
    });
  } else {
    console.log('คอลัมน์ user_id มีอยู่แล้ว');
  }

  // เพิ่มคอลัมน์ status หากยังไม่มี
  if (!hasStatusColumn) {
    db.run("ALTER TABLE notifications ADD COLUMN status TEXT", (err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการเพิ่มคอลัมน์ status:', err);
      } else {
        console.log('เพิ่มคอลัมน์ status เรียบร้อยแล้ว');
      }
    });
  } else {
    console.log('คอลัมน์ status มีอยู่แล้ว');
  }
});*/

// เส้นทางสำหรับยืนยันการแลกเปลี่ยน
app.post('/confirm-exchange', (req, res) => {
    const { user_name, user_id, user_profile_image } = req.body;
    console.log('คำร้องแลกเปลี่ยนที่ได้รับ:', req.body);
  
    // สมมติว่าคุณยังคงต้องการใช้โปรไฟล์ของผู้ส่งจาก session
    const senderProfileImage = req.session.profile_image || '/images/default-profile.png'; // ค่าเริ่มต้น
    const senderName = req.session.userName;

    const sql = `INSERT INTO notifications (user_profile_image, user_name, message, status, user_id)
                 VALUES (?, ?, ?, 'pending', ?)`;
    const params = [senderProfileImage, senderName, `ต้องการสินค้าของคุณ`, user_id];
    db.run(sql, params, function(err) {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการยืนยันการแลกเปลี่ยน:', err.message);
        return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการยืนยันการแลกเปลี่ยน' });    
      }
      res.json({ message: 'ยืนยันการแลกเปลี่ยนสำเร็จ', id: this.lastID });
    });
});

// เส้นทางสำหรับยอมรับการแจ้งเตือน
app.post('/accept-notification', (req, res) => {
    const notificationId = req.body.id;
    console.log('Received notificationId:', notificationId); // Log this to check the value
  
    const db = new sqlite3.Database(dbPath);
    
    db.serialize(() => {
      db.run("UPDATE notifications SET status = 'ได้รับการแลกเปลี่ยนแล้ว' WHERE id = ?", [notificationId], function(err) {
        if (err) {
          console.error('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน:', err);
          res.status(500).send('เกิดข้อผิดพลาดในการอัพเดตสถานะการแจ้งเตือน');
        } else {
          console.log(`การแจ้งเตือน ID ${notificationId} ถูกอัพเดตสถานะเรียบร้อยแล้ว`);
          res.send('การแจ้งเตือนถูกอัพเดตสถานะเรียบร้อยแล้ว');
        }
      });
    });
    
    db.close((err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการปิดฐานข้อมูล:', err);
      } else {
        console.log('ปิดฐานข้อมูลเรียบร้อยแล้ว');
      }
    });
  });  
  
  // เส้นทางสำหรับปฏิเสธการแจ้งเตือน
  app.post('/reject-notification', (req, res) => {
    const { id } = req.body;
    const db = new sqlite3.Database(dbPath);

    const sql = `DELETE FROM notifications WHERE id = ?`;
    db.run(sql, [id], function(err) {
        if (err) {
            console.error('Error rejecting notification:', err.message);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการปฏิเสธการแจ้งเตือน' });
        }
        res.json({ message: 'การแจ้งเตือนถูกปฏิเสธแล้ว' });
    });

    db.close((err) => {
      if (err) {
        console.error('เกิดข้อผิดพลาดในการปิดฐานข้อมูล:', err);
      } else {
        console.log('ปิดฐานข้อมูลเรียบร้อยแล้ว');
      }
    });
});

// เส้นทางสำหรับแสดงหน้าการแจ้งเตือน
app.get('/notifications', (req, res) => {
    const sql = `SELECT * FROM notifications`;
    db.all(sql, [], (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลการแจ้งเตือน' });
      }
      res.render('notifications', {
        name: req.session.userName, // ส่งค่าชื่อผู้ใช้ไปยังหน้า notifications.ejs
        notifications: rows // ส่งตัวแปร notifications ไปด้วย
      });
    });
  });

// เส้นทางสำหรับแสดงหน้าโปรไฟล์ผู้ใช้
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = `SELECT * FROM users WHERE id = ?`;
    console.log('เข้าสู่เส้นทาง /user/:id');
    console.log('User ID:', userId);

    db.get(sql, [userId], (err, row) => {
        if (err) {
            console.error('เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', err);
            return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้' });
        }
        if (!row) {
            console.log('ไม่พบผู้ใช้สำหรับ ID:', userId);
            return res.status(404).send('ไม่พบผู้ใช้');
        }
        console.log('พบข้อมูลผู้ใช้:', row);
        res.render('user', { 
            name: req.session.userName,
            user: row });
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



// เส้นทางสำหรับแก้ไขสินค้า (GET)
app.get('/edit-product/:product_id', ifNotLoggedIn, function (req, res) {
    const productId = req.params.product_id;
    const query = 'SELECT * FROM products WHERE id = ?';

    dbConnection.execute(query, [productId])
        .then(([rows]) => {
            if (rows.length > 0) {
                const product = rows[0];
                // ตรวจสอบว่าผู้ใช้เป็นเจ้าของสินค้าหรือไม่
                if (product.user_id !== req.session.userID) {
                    return res.status(403).send('คุณไม่มีสิทธิ์ในการแก้ไขผลิตภัณฑ์นี้');
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
                    return res.status(403).send('คุณไม่มีสิทธิ์ในการลบผลิตภัณฑ์นี้');
                }
                return dbConnection.execute(deleteQuery, [productId]);
            } else {
                return res.status(404).send('ไม่พบผลิตภัณฑ์');
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
                res.status(500).send('เกิดข้อผิดพลาดขณะลบผลิตภัณฑ์');
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











// Handle chat message
io.on('connection', (socket) => {
    console.log('A user connected');
    const userName = socket.handshake.query.userName;

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });

    socket.on('chat message', (msg) => {
        const userID = msg.userID;
        const messageData = {
            user_id: userID,
            user_name: userName,
            message: msg.message,
            product_user: msg.productUser,
            timestamp: new Date(),
            time: new Date().toLocaleTimeString()
        };
        // Save message to database
        dbConnection.execute(
            'INSERT INTO chat_messages (user_id, user_name, message, product_user, timestamp) VALUES (?, ?, ?, ?, ?)',
            [messageData.user_id, messageData.user_name, messageData.message, messageData.product_user, messageData.timestamp]
        ).then(result => {
            io.emit('chat message', messageData);
        }).catch(err => {
            console.error(err);
        });
    });

    socket.on('chat image', (msg) => {
        const userID = msg.userID;
        const imageData = {
            user_id: userID,
            user_name: userName,
            image_url: msg.imageUrl,
            product_user: msg.productUser,
            timestamp: new Date(),
            time: new Date().toLocaleTimeString()
        };
        // Save image message to database
        dbConnection.execute(
            'INSERT INTO chat_messages (user_id, user_name, product_user, timestamp, image_url) VALUES (?, ?, ?, ?, ?)',
            [imageData.user_id, imageData.user_name, imageData.product_user, imageData.timestamp, imageData.image_url]
        ).then(result => {
            io.emit('chat image', imageData);
        }).catch(err => {
            console.error(err);
        });
    });
});


















// Get chat history and render the save-offer page
app.get('/save-offer', ifNotLoggedIn, (req, res) => {
    dbConnection.execute(
        'SELECT * FROM chat_messages WHERE user_id = ? ORDER BY timestamp ASC',
        [req.session.userID] // เพิ่ม req.session.userID เป็นค่า parameter ใน SQL query
    ).then(([rows]) => {
        res.render('save-offer', {
            name: req.session.userName,
            messages: rows // Pass the messages data to the save-offer template
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
        // Format timestamp before sending to client
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



// Start server
server.listen(3000, () => console.log("Server is running..."));
