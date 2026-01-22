<?php
// Migration script to make username the primary key for users table
error_reporting(E_ALL);
ini_set('display_errors', 1);

include("connection.php");

// Check if users table has id column
$result = mysqli_query($conn, "SHOW COLUMNS FROM users LIKE 'id'");
if (mysqli_num_rows($result) > 0) {
    // Drop the id column
    mysqli_query($conn, "ALTER TABLE users DROP COLUMN id");
    echo "Dropped id column from users table<br>";
}

// Check if username is already primary key
$result = mysqli_query($conn, "SHOW KEYS FROM users WHERE Key_name = 'PRIMARY'");
$primaryKey = mysqli_fetch_assoc($result);
if ($primaryKey['Column_name'] !== 'username') {
    // Add primary key to username
    mysqli_query($conn, "ALTER TABLE users ADD PRIMARY KEY (username)");
    echo "Made username the primary key<br>";
} else {
    echo "Username is already the primary key<br>";
}

echo "Migration completed successfully!";
?>