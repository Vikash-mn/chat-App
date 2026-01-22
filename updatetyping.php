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

if (!isset($_POST['roomname']) || !isset($_POST['username']) || !isset($_POST['is_typing'])) {
    echo json_encode(['error' => 'Missing parameters']);
    exit();
}

$roomname = $_POST['roomname'];
$username = $_POST['username'];
$is_typing = (int)($_POST['is_typing']);

if (empty($roomname) || empty($username)) {
    echo json_encode(['error' => 'Room name and username required']);
    exit();
}

// Verify user has access to room
$cookie_name = 'user_token_' . $roomname;
if (!isset($_COOKIE[$cookie_name])) {
    echo json_encode(['error' => 'Access denied']);
    exit();
}

$user_token = $_COOKIE[$cookie_name];
$query = "SELECT username FROM room_users WHERE roomname = ? AND user_token = ? AND removed_at IS NULL";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ss", $roomname, $user_token);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    echo json_encode(['error' => 'Invalid token']);
    exit();
}

// Update typing status
$query = "INSERT INTO typing_indicators (roomname, username, is_typing)
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE
          is_typing = VALUES(is_typing),
          last_updated = CURRENT_TIMESTAMP";

$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ssi", $roomname, $username, $is_typing);

if (mysqli_stmt_execute($stmt)) {
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['error' => 'Failed to update typing status']);
}
?>