# Secure Login System with User Role Management

A full-featured, secure login and user authentication system built with Node.js, Express, and vanilla HTML/CSS/JS. Includes OTP-based multi-factor authentication, JWT authentication, role-based access control (RBAC), and a modern, responsive user dashboard. Ideal for learning or integrating secure login flows into custom web applications.

## Features

- **User Registration & Login** with OTP and reCAPTCHA
- **JWT-based Authentication**
- **Role-Based Access Control (RBAC)** for admin/user features
- **Multi-Factor Authentication (MFA)** via email OTP
- **Client-side Password Strength Validation**
- **CSRF Protection** for all forms and AJAX requests
- **HTTPS/SSL** support (self-signed certificate for local dev)
- **Dashboard** with:
  - User profile section (name, email, profile picture)
  - Profile picture upload
  - Change password option
  - Recent login activity
  - Notifications area
  - Statistics (total logins, last login)
  - Quick links and support widget
  - Theme switcher (light/dark mode)
  - Responsive, modern UI
- **Secure password hashing** (bcrypt)
- **Email notifications** (OTP via Gmail)

## Setup Instructions

1. **Clone the repository**
2. **Install dependencies:**
   ```sh
   npm install
   ```
3. **Generate a self-signed SSL certificate:**
   - Open Git Bash or a terminal and run:
     ```sh
     openssl req -nodes -new -x509 -keyout server.key -out server.cert
     ```
   - Place `server.key` and `server.cert` in the project root.
4. **Configure Gmail for OTP:**
   - Update your Gmail and app password in `server.js` for Nodemailer.
5. **Start the server:**
   ```sh
   node server.js
   ```
6. **Open the app:**
   - Visit `https://localhost:3000` in your browser (accept the self-signed certificate warning).

## API Endpoints

### Authentication & User
- `POST /api/register` — Register a new user
- `POST /api/login` — Login (step 1, sends OTP)
- `POST /api/verify-otp` — Login (step 2, verify OTP)
- `POST /api/change-password` — Change password (JWT required)
- `POST /api/logout` — Logout (JWT required)

### Dashboard Data
- `GET /api/user-profile` — Get user profile info (JWT required)
- `GET /api/notifications` — Get notifications (JWT required)
- `GET /api/login-activity` — Get recent login activity (JWT required)
- `POST /api/upload-profile-pic` — Upload/change profile picture (JWT required, multipart/form-data)

## Security

- **Password Security:** Client-side validation and bcrypt hashing on the server.
- **Multi-Factor Authentication:** OTP sent to user's email for login.
- **Role-Based Access Control:** Admin/user roles enforced via middleware.
- **CSRF Protection:** All forms and AJAX POST requests require a CSRF token.
- **HTTPS/SSL:** All communication is encrypted with a self-signed certificate (for local development).
- **Bot Protection:** Google reCAPTCHA v3 on registration and login.
- **Logging & Monitoring:** User login activity and notifications are tracked per user.

## Best Practices for Production
- Use a CA-signed SSL certificate instead of self-signed.
- Store secrets (JWT secret, email credentials) in environment variables.
- Implement rate limiting on authentication endpoints.
- Integrate centralized logging (e.g., Winston) for audit trails.

## File Structure

- `server.js` — Node.js/Express backend
- `dashboard.html` — Main dashboard UI
- `users.json` — User data storage
- `profile-pics/` — Uploaded profile pictures
- `login form index.css` — Dashboard and form styles
- `server.key` / `server.cert` — SSL certificate and key (local dev)

## Notes
- Make sure to install all dependencies (`npm install`).
- For email/OTP, you must use a valid Gmail and app password.
- JWT tokens are stored in localStorage and sent with each API request.
- Profile picture uploads require the `multer` package (installed via npm).
- Accept the browser warning for the self-signed certificate when using HTTPS locally.

---

**Enjoy your modern, secure login dashboard!** 
