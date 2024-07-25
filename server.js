
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const path = require('path')

const authRoutes = require('./routes/auth');



const app = express();

//db name and connection
const db = process.env.DB;

mongoose.connect(db, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Successfully connected to MongoDB"))
    .catch(err => console.log(err));


// app.use("/assets", express.static('./assets'));
// app.set('views', path.join(__dirname, 'views'));
// app.set('view engine', 'ejs');


// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// app.use('/', require('./routes/index'));
app.use('/auth', authRoutes);


const PORT = process.env.PORT || 3000;
app.listen(PORT, console.log(`Server running on PORT ${PORT}`));