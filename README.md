# Galaxy Chat Room System 🌌

A modern, real-time chat application that allows users to create and join password-protected chat rooms with a beautiful galaxy-themed interface. Built with PHP, MySQL, and vanilla JavaScript for optimal performance and security.

## 🌟 Key Features

### 🔐 Authentication & Security
- **Secure Registration/Login**: Email validation, password strength checking, session management
- **Password Requirements**: Minimum 6 characters with strength indicator
- **Session Security**: Token-based authentication with automatic timeout
- **CSRF Protection**: All forms protected against cross-site request forgery
- **SQL Injection Prevention**: Prepared statements throughout the application

### 💬 Real-Time Communication
- **Live Messaging**: Instant message delivery with AJAX polling
- **Typing Indicators**: Real-time typing status with 2-second timeout
- **Online Status**: Live user presence tracking with auto-updates
- **Message History**: Persistent chat history with timestamps
- **Emoji Support**: Unicode emoji compatibility

### 👥 Room Management
- **Create Rooms**: Custom room names (2-15 chars, alphanumeric only)
- **Password Protection**: Secure room access with hashed passwords
- **Member Limits**: Support for multiple users per room
- **Room Settings**: Customizable room properties and permissions
- **Display Photos**: Upload custom room images (JPG, PNG, GIF)

### 🎨 User Experience
- **Galaxy Theme**: Beautiful space-themed UI with animations
- **Dark/Light Mode**: Persistent theme preference storage
- **Responsive Design**: Mobile-first approach, works on all devices
- **Profile Management**: Avatar upload and user preferences
- **Smooth Animations**: CSS transitions and floating effects

### 👑 Admin Features
- **Room Control**: Full administrative control for room creators
- **Member Management**: Invite, remove, and manage room members
- **Join Requests**: Approve/deny membership applications
- **Admin Privileges**: Grant admin rights to other users
- **Room Customization**: Update name, password, description, display photo

### 📁 File Management System
- **Avatar Uploads**: User profile pictures with size validation
- **Room Photos**: Custom room display images
- **File Security**: Type and size restrictions (5MB max)
- **Admin Controls**: Complete file management through admin panel
- **Storage Organization**: Automatic file organization by room

## 🛠️ Technical Specifications

### System Requirements
- **Web Server**: Apache/Nginx/IIS with PHP support
- **PHP Version**: 7.0 or higher (recommended: 7.4+)
- **MySQL Version**: 5.7 or higher (recommended: 8.0+)
- **Memory**: 64MB minimum, 128MB recommended
- **Disk Space**: 50MB minimum (plus user uploads)

### PHP Extensions Required
- **mysqli**: Database connectivity
- **mbstring**: Multi-byte string support
- **json**: JSON data handling
- **session**: Session management
- **gd** (optional): Image processing
- **fileinfo** (optional): File type detection

### Browser Support
- **Chrome**: 90+ ✅
- **Firefox**: 88+ ✅
- **Safari**: 14+ ✅
- **Edge**: 90+ ✅
- **Opera**: 76+ ✅
- **Mobile**: iOS Safari 14+, Chrome Mobile 90+

## 🚀 Installation & Setup

### 1. Environment Setup
```bash
# Create project directory
mkdir galaxy-chat
cd galaxy-chat

# Set proper permissions
chmod 755 .
```

### 2. Database Configuration
```bash
# Access phpMyAdmin or MySQL CLI
# Create database: 'chatapp'
# Set charset: utf8mb4
# Collation: utf8mb4_unicode_ci
```

### 3. File Structure Setup
```bash
# Create required directories
mkdir -p uploads/avatars
mkdir -p uploads/room_photos
mkdir -p p/backup_useless_files

# Set permissions
chmod -R 755 uploads/
chmod -R 777 p/  # For backup operations
```

### 4. Database Initialization
- Navigate to `http://localhost/galaxy-chat/db_setup.php`
- Or run via command line: `php db_setup.php`
- Verify all 8 tables are created successfully

### 5. System Verification
- Run `test_system.php` to verify installation
- Check all components: database, files, permissions, PHP extensions
- Ensure no critical errors are reported

## 📁 Complete File Structure

```
galaxy-chat/
├── 🏠 Core Application Files
│   ├── index.php              # Main dashboard (create/join rooms)
│   ├── room.php               # Chat room interface (2728 lines)
│   ├── welcome.php            # Landing/welcome page
│   ├── login.php              # User authentication
│   ├── signup.php             # User registration (347 lines)
│   ├── logout.php             # Session termination
│   ├── profile.php            # User profile management
│   └── admin.php              # Administrative panel
│
├── 🔧 Backend Processing
│   ├── connection.php         # Database connection & security (116 lines)
│   ├── session_manager.php    # Session handling utilities
│   ├── db_setup.php           # Database initialization (195 lines)
│   ├── postmsg.php            # Message posting handler
│   ├── fetchmessages.php      # AJAX message retrieval
│   ├── fetchonlineusers.php   # Online users fetching
│   ├── fetchtyping.php        # Typing status fetching
│   ├── updatetyping.php       # Typing indicator updates
│   ├── updateonlinestatus.php # Online status management
│   ├── save_preference.php    # User preferences handler
│   ├── load_preferences.php   # Preference loading
│   ├── get_room_members.php   # Room member management
│   ├── save_room_settings.php # Room settings handler
│   ├── update_room_settings.php # Room updates
│   ├── invite_member.php      # Member invitation system
│   ├── remove_member.php      # Member removal
│   ├── make_admin.php         # Admin privilege management
│   ├── approve_request.php    # Join request approval
│   ├── deny_request.php       # Join request denial
│   └── get_pending_requests.php # Pending requests viewer
│
├── 🎨 Frontend Assets
│   ├── galaxy-theme.css       # Main styling (1606+ lines)
│   └── index.html             # Static HTML version
│
├── 📊 Administrative Tools
│   ├── ADMIN_FILE_MANAGEMENT.md # File management guide (162 lines)
│   ├── test_system.php        # System diagnostics (203 lines)
│   ├── test_notification_system.php # Notification testing
│   └── create_join_requests_table.php # Database utilities
│
├── 📄 Documentation
│   └── README.md              # This comprehensive guide
│
├── 📁 Upload Directories
│   ├── uploads/               # Main uploads directory
│   │   ├── avatars/          # User profile pictures
│   │   └── room_photos/      # Room display images
│   └── p/                    # Backup directory
│       └── backup_useless_files/ # Archive storage
│
└── 🔒 Security Features
    ├── Input validation and sanitization
    ├── CSRF token protection
    ├── Prepared statement queries
    ├── Password hashing (PHP password_hash)
    └── Session security with tokens
```

## 🗄️ Database Architecture

### Complete Table Schema

#### `users` - User Management
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    profile_photo VARCHAR(255) DEFAULT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_is_online (is_online)
);
```

#### `rooms` - Room Configuration
```sql
CREATE TABLE rooms (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    creator VARCHAR(50) NOT NULL,
    display_photo VARCHAR(255) DEFAULT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_roomname (roomname),
    INDEX idx_creator (creator)
);
```

#### `room_users` - Membership Management
```sql
CREATE TABLE room_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    user_token VARCHAR(64) NOT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_room_user (roomname, username),
    INDEX idx_roomname (roomname),
    INDEX idx_username (username),
    INDEX idx_user_token (user_token)
);
```

#### `messages` - Chat Data
```sql
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    msg TEXT NOT NULL,
    roomname VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_roomname (roomname),
    INDEX idx_username (username),
    INDEX idx_created_at (created_at)
);
```

#### `typing_indicators` - Real-time Status
```sql
CREATE TABLE typing_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    is_typing BOOLEAN NOT NULL DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_room_user_typing (roomname, username),
    INDEX idx_roomname (roomname),
    INDEX idx_is_typing (is_typing)
);
```

#### `user_preferences` - User Settings
```sql
CREATE TABLE user_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    preference_key VARCHAR(50) NOT NULL,
    preference_value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_preference (username, preference_key),
    INDEX idx_username (username)
);
```

#### `room_admins` - Admin Privileges
```sql
CREATE TABLE room_admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    granted_by VARCHAR(50) NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_room_admin (roomname, username),
    INDEX idx_roomname (roomname),
    INDEX idx_username (username)
);
```

#### `join_requests` - Membership Requests
```sql
CREATE TABLE join_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(50) NOT NULL,
    username VARCHAR(50) NOT NULL,
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'approved', 'denied') DEFAULT 'pending',
    UNIQUE KEY unique_request (roomname, username),
    INDEX idx_roomname (roomname),
    INDEX idx_username (username),
    INDEX idx_status (status)
);
```

## 🔌 API Endpoints

### Authentication Endpoints
- `POST /login.php` - User login processing
- `POST /signup.php` - User registration
- `GET /logout.php` - Session termination
- `GET /profile.php` - Profile management

### Room Management
- `GET /room.php?roomname={name}` - Chat room interface
- `POST /index.php` - Create or join room
- `GET /get_room_members.php?roomname={name}` - Room member list
- `POST /save_room_settings.php` - Update room settings
- `POST /update_room_settings.php` - Room modifications

### Real-Time Communication
- `GET /fetchmessages.php?roomname={name}&last_id={id}` - Message polling
- `POST /postmsg.php` - Send message
- `GET /fetchonlineusers.php?roomname={name}` - Online users
- `GET /fetchtyping.php?roomname={name}` - Typing status
- `POST /updatetyping.php` - Update typing indicator
- `POST /updateonlinestatus.php` - Update online status

### Admin Functions
- `GET /admin.php` - Admin panel (password: 2676)
- `POST /approve_request.php` - Approve join request
- `POST /deny_request.php` - Deny join request
- `POST /invite_member.php` - Invite user to room
- `POST /remove_member.php` - Remove room member
- `POST /make_admin.php` - Grant admin privileges

### User Management
- `POST /save_preference.php` - Save user preferences
- `GET /load_preferences.php` - Load user settings

## 📱 Responsive Design

### Breakpoint Specifications
- **📱 Mobile**: 320px - 480px
  - Stacked layout, compact header
  - Touch-optimized buttons
  - Simplified navigation
- **📱 Small Tablets**: 481px - 768px
  - Adjusted spacing and font sizes
  - Optimized button layouts
- **📱 Tablets**: 769px - 1024px
  - Balanced layout with side margins
  - Enhanced visual hierarchy
- **💻 Desktops**: 1025px - 1440px
  - Full-width layouts
  - Maximum content width: 1200px
- **🖥️ Large Screens**: 1441px+
  - Centered layouts with max-width
  - Enhanced visual effects

## 🔒 Security Implementation

### Authentication Security
- **Password Hashing**: PHP `password_hash()` with `PASSWORD_DEFAULT`
- **Session Security**: Secure session cookies with `session.cookie_secure`
- **Token Validation**: CSRF tokens on all forms
- **Input Validation**: Server-side validation for all inputs

### Database Security
- **Prepared Statements**: All queries use mysqli prepared statements
- **SQL Injection Prevention**: Parameterized queries throughout
- **Connection Security**: SSL verification for database connections
- **Error Handling**: Secure error logging without information disclosure

### File Upload Security
- **Type Validation**: Only image files allowed (JPG, PNG, GIF)
- **Size Limits**: 5MB maximum file size
- **Path Security**: Secure file path handling
- **Admin Controls**: Complete file management through admin panel

## 🚨 Monitoring & Diagnostics

### System Testing
- **test_system.php**: Comprehensive system diagnostics
- **Database Tests**: Connection, table existence, permissions
- **File Tests**: Required files, directory permissions
- **PHP Tests**: Version compatibility, extension loading
- **Session Tests**: Session configuration validation

### Performance Monitoring
- **Real-time Updates**: 2-second polling intervals
- **Online Status**: 1-minute ping intervals
- **Typing Indicators**: 2-second timeout with cleanup
- **Message Refresh**: 2-second polling cycle

### Error Handling
- **Database Errors**: Logged to `error.log` file
- **Connection Issues**: Graceful degradation with user feedback
- **File Upload Errors**: Detailed error messages and fallbacks
- **JavaScript Errors**: Console logging for debugging

## 🎯 Usage Guide

### For Regular Users

1. **Account Creation**
   - Navigate to signup page
   - Enter username (3-50 chars, alphanumeric + underscore)
   - Provide valid email address
   - Set password (minimum 6 characters)
   - Confirm password matches

2. **Room Creation**
   - Click "Create Room" on main page
   - Enter room name (2-15 characters)
   - Set secure password (minimum 4 characters)
   - Confirm password
   - Room is created instantly

3. **Joining Rooms**
   - Click "Join Room" on main page
   - Enter exact room name
   - Provide correct password
   - Access granted immediately

4. **Chatting**
   - Type messages in input field
   - Press Enter or click Send
   - See typing indicators in real-time
   - View online users in header

### For Room Administrators

1. **Member Management**
   - Access room settings (gear icon)
   - Navigate to Members tab
   - Invite users by username
   - Approve pending join requests
   - Remove unwanted members

2. **Room Customization**
   - Update room name and description
   - Change room password
   - Upload display photo
   - Configure privacy settings

3. **Admin Controls**
   - Grant admin privileges to trusted users
   - Manage notification settings
   - Control media sharing options
   - Set privacy preferences

## 🔧 Advanced Configuration

### Environment Variables
```bash
# Database Configuration
DB_HOST=localhost
DB_USER=your_username
DB_PASS=your_password
DB_NAME=chatapp

# Security Settings
SESSION_TIMEOUT=1800
CSRF_TOKEN_EXPIRY=3600
MAX_FILE_SIZE=5242880

# Performance Settings
MESSAGE_POLL_INTERVAL=2000
TYPING_TIMEOUT=2000
ONLINE_PING_INTERVAL=60000
```

### PHP Configuration
```ini
# php.ini recommended settings
memory_limit = 128M
upload_max_filesize = 5M
post_max_size = 6M
max_file_uploads = 20
max_execution_time = 30

# Security settings
session.cookie_secure = On
session.cookie_httponly = On
session.use_strict_mode = On
```

### MySQL Optimization
```sql
-- Recommended indexes (automatically created)
CREATE INDEX idx_messages_room_time ON messages(roomname, created_at);
CREATE INDEX idx_typing_room_user ON typing_indicators(roomname, username);
CREATE INDEX idx_room_users_token ON room_users(user_token);

-- Performance settings
SET GLOBAL innodb_buffer_pool_size = 134217728; -- 128MB
SET GLOBAL max_connections = 100;
```

## 🚨 Troubleshooting Guide

### Database Issues
- **Connection Failed**: Check credentials in `connection.php`
- **Tables Missing**: Run `db_setup.php` to create tables
- **Permission Denied**: Verify MySQL user privileges
- **Charset Issues**: Ensure UTF8MB4 support

### File Upload Problems
- **Directory Not Writable**: `chmod 755 uploads/`
- **File Too Large**: Increase `upload_max_filesize` in PHP
- **Type Not Allowed**: Check file extension and MIME type
- **Permission Issues**: Verify web server user permissions

### Real-Time Features
- **Messages Not Updating**: Check JavaScript console for AJAX errors
- **Typing Not Showing**: Verify `typing_indicators` table exists
- **Online Users Missing**: Check `updateonlinestatus.php` functionality
- **Slow Updates**: Reduce polling interval or check server performance

### Performance Issues
- **Slow Loading**: Optimize MySQL queries and add indexes
- **High Memory Usage**: Check for memory leaks in long-running scripts
- **Database Timeouts**: Increase `max_execution_time` and `max_connections`
- **File Upload Slow**: Check disk I/O and network connectivity

## 🔍 System Diagnostics

### Using test_system.php
1. Navigate to `test_system.php` in your browser
2. Review all test categories:
   - Database connectivity
   - Table existence
   - File permissions
   - PHP extensions
   - Session configuration

3. Address any failures before proceeding
4. Use the system only when all critical tests pass

### Manual Checks
```bash
# Database connectivity
mysql -u username -p -e "USE chatapp; SHOW TABLES;"

# File permissions
ls -la uploads/
stat uploads/avatars/
stat uploads/room_photos/

# PHP configuration
php -m | grep -E "(mysqli|mbstring|json|session)"
php -i | grep -E "(memory_limit|upload_max_filesize)"
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes following existing code style
4. Test thoroughly on different browsers and devices
5. Submit pull request with detailed description

### Code Standards
- **PHP**: PSR-12 coding standards
- **JavaScript**: ES6+ with proper error handling
- **CSS**: Mobile-first responsive design
- **Security**: Input validation and CSRF protection

### Testing Requirements
- Cross-browser compatibility (Chrome, Firefox, Safari, Edge)
- Mobile responsiveness (iOS, Android)
- Security testing (SQL injection, XSS, CSRF)
- Performance testing (load times, memory usage)

## 📋 Admin Panel Access

### Admin Features
- **File Management**: View, download, delete uploaded files
- **User Monitoring**: Track user activity and room membership
- **System Diagnostics**: View system health and performance
- **Room Management**: Oversee all rooms and memberships

### Admin Credentials
- **URL**: `http://localhost/galaxy-chat/admin.php`
- **Password**: `2676`
- **Access Level**: Full system administration

## 📞 Support & Maintenance

### Regular Maintenance Tasks
1. **Database Backup**: Weekly backup of chatapp database
2. **File Cleanup**: Remove old uploaded files periodically
3. **Log Rotation**: Monitor and rotate `error.log` file
4. **Security Updates**: Keep PHP and MySQL updated
5. **Performance Monitoring**: Check system resources regularly

### Getting Help
1. Check the troubleshooting section above
2. Run `test_system.php` for diagnostics
3. Review browser console for JavaScript errors
4. Check PHP error logs for server-side issues
5. Verify database connectivity and permissions

### Emergency Procedures
1. **System Down**: Check web server status and database connectivity
2. **Data Loss**: Restore from recent database backup
3. **Security Breach**: Change all passwords and review access logs
4. **Performance Issues**: Check server resources and optimize queries

## 📄 Version History

### Current Version: 2.0
- **Real-time messaging** with typing indicators
- **File upload system** with admin management
- **Responsive design** for all devices
- **Dark/light theme** support
- **Comprehensive admin panel**

### Previous Versions
- **Version 1.0**: Basic chat functionality
- **Version 1.5**: Added user authentication and room management

## 🙏 Acknowledgments

- **Development**: Built with PHP, MySQL, JavaScript, and jQuery
- **Styling**: Custom CSS with CSS Grid and Flexbox
- **Fonts**: Google Fonts (Montserrat family)
- **Icons**: Unicode emoji character set
- **Security**: OWASP guidelines and best practices
- **Performance**: Optimized for real-time communication

---

## 🎉 Getting Started

**Ready to start chatting?**

1. **Quick Setup**: Run `db_setup.php` and `test_system.php`
2. **Create Account**: Visit the signup page
3. **Join Chat**: Create or join a room
4. **Start Talking**: Send your first message!

**🌟 Welcome to the Galaxy Chat Room System! 🌟**

For support, troubleshooting, or feature requests, please check the documentation above or run the system diagnostics.