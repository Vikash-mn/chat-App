<?php
// Fix database schema issues
error_reporting(E_ALL);
ini_set('display_errors', 1);

include("connection.php");

// Add id column to users table if it doesn't exist
$result = mysqli_query($conn, "SHOW COLUMNS FROM users LIKE 'id'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE users ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY FIRST");
    echo "✓ Added id column to users table<br>";
} else {
    echo "✓ id column already exists in users table<br>";
}

// Make sure username is unique (not primary if id is primary)
$result = mysqli_query($conn, "SHOW KEYS FROM users WHERE Key_name = 'username'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE users ADD UNIQUE KEY unique_username (username)");
    echo "✓ Added unique constraint on username<br>";
} else {
    echo "✓ Username unique constraint already exists<br>";
}

// Create typing_status table if it doesn't exist (for backward compatibility)
$table_check = mysqli_query($conn, "SHOW TABLES LIKE 'typing_status'");
if (mysqli_num_rows($table_check) == 0) {
    $create_table = "CREATE TABLE typing_status (
        id INT AUTO_INCREMENT PRIMARY KEY,
        roomname VARCHAR(50) NOT NULL,
        username VARCHAR(50) NOT NULL,
        is_typing BOOLEAN NOT NULL DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_room_user (roomname, username),
        INDEX idx_roomname (roomname),
        INDEX idx_is_typing (is_typing)
    )";
    mysqli_query($conn, $create_table);
    echo "✓ Created typing_status table<br>";
} else {
    echo "✓ typing_status table already exists<br>";
}

// Ensure personal_typing_status table exists
$table_check = mysqli_query($conn, "SHOW TABLES LIKE 'personal_typing_status'");
if (mysqli_num_rows($table_check) == 0) {
    $create_table = "CREATE TABLE personal_typing_status (
        id INT AUTO_INCREMENT PRIMARY KEY,
        from_user VARCHAR(50) NOT NULL,
        to_user VARCHAR(50) NOT NULL,
        is_typing BOOLEAN NOT NULL DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_personal_typing (from_user, to_user),
        INDEX idx_from_user (from_user),
        INDEX idx_to_user (to_user)
    )";
    mysqli_query($conn, $create_table);
    echo "✓ Created personal_typing_status table<br>";
} else {
    echo "✓ personal_typing_status table already exists<br>";
}

// Ensure admin_users table exists
$table_check = mysqli_query($conn, "SHOW TABLES LIKE 'admin_users'");
if (mysqli_num_rows($table_check) == 0) {
    $create_table = "CREATE TABLE admin_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        role ENUM('admin', 'moderator') DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        is_active BOOLEAN DEFAULT TRUE,
        INDEX idx_username (username),
        INDEX idx_email (email)
    )";
    mysqli_query($conn, $create_table);
    echo "✓ Created admin_users table<br>";
} else {
    echo "✓ admin_users table already exists<br>";
}

// Add user_agent column to admin_users if missing
$result = mysqli_query($conn, "SHOW COLUMNS FROM admin_users LIKE 'user_agent'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE admin_users ADD COLUMN user_agent TEXT");
    echo "✓ Added user_agent column to admin_users<br>";
}

// Add missing columns to personal_messages
$result = mysqli_query($conn, "SHOW COLUMNS FROM personal_messages LIKE 'message_type'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE personal_messages ADD COLUMN message_type ENUM('text', 'image', 'file') DEFAULT 'text'");
    echo "✓ Added message_type column to personal_messages<br>";
}

$result = mysqli_query($conn, "SHOW COLUMNS FROM personal_messages LIKE 'file_path'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE personal_messages ADD COLUMN file_path VARCHAR(255) DEFAULT NULL");
    echo "✓ Added file_path column to personal_messages<br>";
}

$result = mysqli_query($conn, "SHOW COLUMNS FROM personal_messages LIKE 'file_size'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE personal_messages ADD COLUMN file_size INT DEFAULT NULL");
    echo "✓ Added file_size column to personal_messages<br>";
}

$result = mysqli_query($conn, "SHOW COLUMNS FROM personal_messages LIKE 'is_deleted'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE personal_messages ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE");
    echo "✓ Added is_deleted column to personal_messages<br>";
}

echo "<br><strong>Database fixes completed!</strong><br>";
echo "<a href='index.php'>Go to Chat Application</a>";
?>