const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";

const User = require('../models/User');

// Helper function to handle rendering errors
function renderErrorPage(res, template, errors, data = {}) {
    res.render(template, { errors, ...data });
}

// Helper function to send emails
async function sendEmail(transporter, mailOptions) {
    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Mail sent:', info.response);
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

exports.registerHandle = async (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please enter all fields' });
    }

    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }

    if (errors.length > 0) {
        renderErrorPage(res, 'register', errors, { name, email, password, password2 });
    } else {
        try {
            const user = await User.findOne({ email });
            if (user) {
                errors.push({ msg: 'Email ID already registered' });
                renderErrorPage(res, 'register', errors, { name, email, password, password2 });
            } else {
                // Rest of the code for sending activation email and saving user
            }
        } catch (error) {
            console.error('Error during registration:', error);
            renderErrorPage(res, 'register', [{ msg: 'Something went wrong. Please try again.' }]);
        }
    }
}

// Similar optimizations can be applied to other functions as well

// Exported functions...


//------------ Activate Account Handle ------------//
exports.activateHandle = async (req, res) => {
    const token = req.params.token;

    try {
        const decodedToken = jwt.verify(token, JWT_KEY);
        const { name, email, password } = decodedToken;

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            req.flash('error_msg', 'Email ID already registered! Please log in.');
            res.redirect('/auth/login');
        } else {
            const salt = await bcryptjs.genSalt(10);
            const hash = await bcryptjs.hash(password, salt);

            const newUser = new User({
                name,
                email,
                password: hash,
            });

            await newUser.save();

            req.flash('success_msg', 'Account activated. You can now log in.');
            res.redirect('/auth/login');
        }
    } catch (error) {
        req.flash('error_msg', 'Incorrect or expired link! Please register again.');
        res.redirect('/auth/register');
    }
};

//------------ Forgot Password Handle ------------//
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    let errors = [];

    if (!email) {
        errors.push({ msg: 'Please enter an email ID' });
        res.render('forgot', { errors, email });
    } else {
        try {
            const user = await User.findOne({ email });

            if (!user) {
                errors.push({ msg: 'User with Email ID does not exist!' });
                res.render('forgot', { errors, email });
            } else {
                const oauth2Client = createOAuth2Client();
                oauth2Client.setCredentials({
                    refresh_token: '1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w',
                });
                const accessToken = oauth2Client.getAccessToken();

                const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;
                const resetLink = `${CLIENT_URL}/auth/forgot/${token}`;

                await User.updateOne({ resetLink });

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: 'OAuth2',
                        user: 'nodejsa@gmail.com',
                        clientId: '173872994719-pvsnau5mbj47h0c6ea6ojrl7gjqq1908.apps.googleusercontent.com',
                        clientSecret: 'OKXIYR14wBB_zumf30EC__iJ',
                        refreshToken:
                            '1//04T_nqlj9UVrVCgYIARAAGAQSNwF-L9IrGm-NOdEKBOakzMn1cbbCHgg2ivkad3Q_hMyBkSQen0b5ABfR8kPR18aOoqhRrSlPm9w',
                        accessToken,
                    },
                });

                const mailOptions = {
                    from: '"Auth Admin" <nodejsa@gmail.com>',
                    to: email,
                    subject: 'Account Password Reset: NodeJS Auth ✔',
                    html: `<h2>Please click on below link to reset your account password</h2><p>${resetLink}</p><p><b>NOTE: </b> The activation link expires in 30 minutes.</p>`,
                };

                await sendEmail(transporter, mailOptions);

                req.flash('success_msg', 'Password reset link sent to email ID. Please follow the instructions.');
                res.redirect('/auth/login');
            }
        } catch (error) {
            console.error('Error during password reset:', error);
            req.flash('error_msg', 'Something went wrong on our end. Please try again later.');
            res.redirect('/auth/forgot');
        }
    }
};


//------------ Redirect to Reset Handle ------------//
exports.gotoReset = async (req, res) => {
    const { token } = req.params;

    if (!token) {
        console.log('Password reset error!');
        return;
    }

    try {
        const decodedToken = jwt.verify(token, JWT_RESET_KEY);
        const { _id } = decodedToken;

        const user = await User.findById(_id);

        if (!user) {
            req.flash('error_msg', 'User with email ID does not exist! Please try again.');
            res.redirect('/auth/login');
        } else {
            res.redirect(`/auth/reset/${_id}`);
        }
    } catch (error) {
        req.flash('error_msg', 'Incorrect or expired link! Please try again.');
        res.redirect('/auth/login');
    }
};

exports.resetPassword = async (req, res) => {
    const { password, password2 } = req.body;
    const id = req.params.id;

    try {
        let errors = [];

        //------------ Checking required fields ------------//
        if (!password || !password2) {
            errors.push('Please enter all fields.');
        }

        //------------ Checking password length ------------//
        if (password.length < 8) {
            errors.push('Password must be at least 8 characters.');
        }

        //------------ Checking password mismatch ------------//
        if (password !== password2) {
            errors.push('Passwords do not match.');
        }

        if (errors.length > 0) {
            req.flash('error_msg', errors);
            res.redirect(`/auth/reset/${id}`);
            return;
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(password, salt);

        await User.findByIdAndUpdate({ _id: id }, { password: hash });

        req.flash('success_msg', 'Password reset successfully!');
        res.redirect('/auth/login');
    } catch (error) {
        req.flash('error_msg', 'Error resetting password!');
        res.redirect(`/auth/reset/${id}`);
    }
};


//------------ Login Handle ------------//
exports.loginHandle = async (req, res, next) => {
    try {
        passport.authenticate('local', {
            successRedirect: '/dashboard',
            failureRedirect: '/auth/login',
            failureFlash: true
        })(req, res, next);
    } catch (error) {
        req.flash('error_msg', 'Login failed. Please try again.');
        res.redirect('/auth/login');
    }
};


//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
    try {
        req.logout(()=>{
            req.flash('success_msg', 'You are logged out');
            res.redirect('/auth/login');
        });
        
    } catch (error) {
        req.flash('error_msg', 'Error logging out');
        res.redirect('/dashboard'); // Redirect to a suitable page on error
    }
};

