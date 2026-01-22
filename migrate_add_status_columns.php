<?php
// Disable mysqli exceptions to prevent fatal errors
mysqli_report(MYSQLI_REPORT_OFF);

include("connection.php");

echo "<!DOCTYPE html>
<html>
<head>
    <title>Add Missing Columns Migration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .success { background: #d4edda; border-color: #c3e6cb; color: #155724; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .error { background: #f8d7da; border-color: #f5c6cb; color: #721c24; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .info { background: #d1ecf1; border-color: #bee5eb; color: #0c5460; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class='container'>
        <h1>🔧 Database Migration: Add Missing Columns</h1>
        <p>This script will add missing columns to the rooms and room_users tables.</p>";

// Migration for rooms table
$rooms_alterations = [
    "status" => "ALTER TABLE rooms ADD COLUMN status ENUM('active', 'inactive') DEFAULT 'active'",
    "deleted_at" => "ALTER TABLE rooms ADD COLUMN deleted_at TIMESTAMP NULL",
    "is_private" => "ALTER TABLE rooms ADD COLUMN is_private BOOLEAN DEFAULT FALSE",
    "max_members" => "ALTER TABLE rooms ADD COLUMN max_members INT DEFAULT 100",
    "settings" => "ALTER TABLE rooms ADD COLUMN settings TEXT",
    "theme" => "ALTER TABLE rooms ADD COLUMN theme VARCHAR(50) DEFAULT 'default'",
    "welcome_message" => "ALTER TABLE rooms ADD COLUMN welcome_message TEXT"
];

echo "<h2>Updating rooms table...</h2>";
foreach ($rooms_alterations as $column => $query) {
    // Check if column already exists
    $check_query = "SHOW COLUMNS FROM rooms LIKE '$column'";
    $result = mysqli_query($conn, $check_query);
    if (mysqli_num_rows($result) > 0) {
        echo "<div class='info'>ℹ️ Column '$column' already exists, skipping...</div>";
        mysqli_free_result($result);
        continue;
    }
    mysqli_free_result($result);

    echo "<p>Executing: <code>$query</code></p>";

    if (mysqli_query($conn, $query)) {
        echo "<div class='success'>✅ Column '$column' added successfully!</div>";
    } else {
        echo "<div class='error'>❌ Error adding column '$column': " . mysqli_error($conn) . "</div>";
    }
}

// Migration for users table
$users_alterations = [
    "role" => "ALTER TABLE users ADD COLUMN role ENUM('user', 'admin') DEFAULT 'user'"
];

echo "<h2>Updating users table...</h2>";
foreach ($users_alterations as $column => $query) {
    // Check if column already exists
    $check_query = "SHOW COLUMNS FROM users LIKE '$column'";
    $result = mysqli_query($conn, $check_query);
    if (mysqli_num_rows($result) > 0) {
        echo "<div class='info'>ℹ️ Column '$column' already exists, skipping...</div>";
        mysqli_free_result($result);
        continue;
    }
    mysqli_free_result($result);

    echo "<p>Executing: <code>$query</code></p>";

    if (mysqli_query($conn, $query)) {
        echo "<div class='success'>✅ Column '$column' added successfully!</div>";
    } else {
        echo "<div class='error'>❌ Error adding column '$column': " . mysqli_error($conn) . "</div>";
    }
}

// Migration for room_users table
$room_users_alterations = [
    "status" => "ALTER TABLE room_users ADD COLUMN status ENUM('active', 'removed') DEFAULT 'active'",
    "joined_at" => "ALTER TABLE room_users ADD COLUMN joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    "last_active" => "ALTER TABLE room_users ADD COLUMN last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
    "removed_at" => "ALTER TABLE room_users ADD COLUMN removed_at TIMESTAMP NULL",
    "removed_by" => "ALTER TABLE room_users ADD COLUMN removed_by VARCHAR(50) NULL"
];

echo "<h2>Updating room_users table...</h2>";
foreach ($room_users_alterations as $column => $query) {
    // Check if column already exists
    $check_query = "SHOW COLUMNS FROM room_users LIKE '$column'";
    $result = mysqli_query($conn, $check_query);
    if (mysqli_num_rows($result) > 0) {
        echo "<div class='info'>ℹ️ Column '$column' already exists, skipping...</div>";
        mysqli_free_result($result);
        continue;
    }
    mysqli_free_result($result);

    echo "<p>Executing: <code>$query</code></p>";

    if (mysqli_query($conn, $query)) {
        echo "<div class='success'>✅ Column '$column' added successfully!</div>";
    } else {
        echo "<div class='error'>❌ Error adding column '$column': " . mysqli_error($conn) . "</div>";
    }
}

echo "<div class='success'>🎉 Migration completed! The database should now support all features.</div>";
echo "<p><a href='room.php?roomname=test'>Test: Enter a room</a></p>";
echo "<p><a href='index.php'>Go to Chat Application</a></p>";

echo "    </div>
</body>
</html>";
?>