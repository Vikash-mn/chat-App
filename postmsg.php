<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Invalid request method']);
    exit();
}

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

if (!isset($_POST['message']) || !isset($_POST['room'])) {
    echo json_encode(['error' => 'Missing parameters']);
    exit();
}

$username = $_SESSION['username'];
// === CHANGE THIS LINE ===
// Old: $message = trim($_POST['message']);
$message = sanitizeInput($_POST['message']); 
// ========================
$roomname = $_POST['room'];

if (empty($message)) {
    echo json_encode(['error' => 'Empty message']);
    exit();
}

// Use prepared statement
$query = "INSERT INTO messages (username, msg, roomname) VALUES (?, ?, ?)";
// ... [Rest of the file remains the same]
$stmt = mysqli_prepare($conn, $query);

if (!$stmt) {
    echo json_encode(['error' => 'Prepare failed: ' . mysqli_error($conn)]);
    exit();
}

mysqli_stmt_bind_param($stmt, "sss", $username, $message, $roomname);

if (!mysqli_stmt_execute($stmt)) {
    echo json_encode(['error' => 'Execute failed: ' . mysqli_error($conn)]);
    exit();
}

echo json_encode(['success' => true]);
?>