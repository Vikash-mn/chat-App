<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$username = $_SESSION['username'];
$preference_key = $_POST['key'] ?? '';
$preference_value = $_POST['value'] ?? '';

if (empty($preference_key)) {
    echo json_encode(['error' => 'Missing preference key']);
    exit();
}

// Check if table exists
$tableExists = mysqli_query($conn, "SHOW TABLES LIKE 'user_preferences'");

if (!$tableExists || mysqli_num_rows($tableExists) == 0) {
    echo json_encode(['error' => 'User preferences table not found. Please run database migration first.']);
    exit();
}

// Save or update the preference
$query = "INSERT INTO user_preferences (username, preference_key, preference_value)
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE preference_value = ?, updated_at = CURRENT_TIMESTAMP";

$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ssss", $username, $preference_key, $preference_value, $preference_value);

if (mysqli_stmt_execute($stmt)) {
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['error' => 'Database error']);
}
?>