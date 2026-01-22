<?php
// Migration script to add role column to admin_users table
error_reporting(E_ALL);
ini_set('display_errors', 1);

include("connection.php");

// Check if role column exists, if not add it
$result = mysqli_query($conn, "SHOW COLUMNS FROM admin_users LIKE 'role'");
if (mysqli_num_rows($result) == 0) {
    mysqli_query($conn, "ALTER TABLE admin_users ADD COLUMN role ENUM('admin', 'master') DEFAULT 'admin' AFTER email");
    echo "✓ Added role column to admin_users table<br>";
} else {
    echo "✓ Role column already exists<br>";
}

// Update existing admin user to master role if not already set
$result = mysqli_query($conn, "SELECT id FROM admin_users WHERE username = 'admin' AND (role IS NULL OR role = '')");
if (mysqli_num_rows($result) > 0) {
    mysqli_query($conn, "UPDATE admin_users SET role = 'master' WHERE username = 'admin'");
    echo "✓ Updated admin user to master role<br>";
} else {
    echo "✓ Admin user already has master role<br>";
}

mysqli_close($conn);
echo "<br><strong>Migration completed successfully!</strong><br>";
?>