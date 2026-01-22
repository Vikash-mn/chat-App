<?php
// Migration script to create admin_users table for database-based admin authentication
error_reporting(E_ALL);
ini_set('display_errors', 1);

include("connection.php");

// Create admin_users table if it doesn't exist
$table_sql = "CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'master') DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_username (username),
    INDEX idx_is_active (is_active),
    INDEX idx_role (role)
)";

if (mysqli_query($conn, $table_sql)) {
    echo "✓ admin_users table created successfully<br>";
} else {
    echo "✗ Error creating admin_users table: " . mysqli_error($conn) . "<br>";
    exit();
}

// Insert default master admin user if not exists
$default_username = 'admin';
$default_password_hash = password_hash('2676', PASSWORD_DEFAULT);
$default_email = 'admin@localhost';
$default_role = 'master';

$check_sql = "SELECT id FROM admin_users WHERE username = ?";
$stmt = mysqli_prepare($conn, $check_sql);
mysqli_stmt_bind_param($stmt, "s", $default_username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    $insert_sql = "INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)";
    $stmt = mysqli_prepare($conn, $insert_sql);
    mysqli_stmt_bind_param($stmt, "ssss", $default_username, $default_password_hash, $default_email, $default_role);

    if (mysqli_stmt_execute($stmt)) {
        echo "✓ Default master admin user 'admin' created successfully<br>";
    } else {
        echo "✗ Error creating default master admin user: " . mysqli_error($conn) . "<br>";
    }
    mysqli_stmt_close($stmt);
} else {
    echo "✓ Default master admin user already exists<br>";
}

mysqli_stmt_close($stmt);
mysqli_close($conn);

echo "<br><strong>Migration completed successfully!</strong><br>";
echo "<a href='admin.php'>Go to Admin Panel</a>";
?>