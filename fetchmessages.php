<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$roomname = $_GET['roomname'] ?? '';
$last_id = (int)($_GET['last_id'] ?? 0);

if (empty($roomname)) {
    echo json_encode(['error' => 'Room name required']);
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

$user = mysqli_fetch_assoc($result);
$current_username = $user['username'];

// Fetch messages
$query = "SELECT id, username, msg, created_at FROM messages WHERE roomname = ? AND id > ? ORDER BY id ASC";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "si", $roomname, $last_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$messages = [];
$last_id = $last_id;

while ($row = mysqli_fetch_assoc($result)) {
    $messages[] = [
        'id' => $row['id'],
        'username' => $row['username'],
        'message' => $row['msg'],
        'time' => $row['created_at'],
        'isCurrentUser' => ($row['username'] === $current_username)
    ];
    $last_id = $row['id'];
}

echo json_encode([
    'success' => true,
    'messages' => $messages,
    'last_id' => $last_id
]);
?>