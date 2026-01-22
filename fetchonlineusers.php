<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$roomname = $_GET['roomname'] ?? '';

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
$query = "SELECT username FROM room_users WHERE roomname = ? AND user_token = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ss", $roomname, $user_token);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    echo json_encode(['error' => 'Invalid token']);
    exit();
}

// Get online users in the room (users who have been active in the last 5 minutes)
$query = "SELECT DISTINCT u.username, u.profile_photo, u.last_seen
          FROM users u
          INNER JOIN room_users ru ON u.username = ru.username
          WHERE ru.roomname = ? AND ru.removed_at IS NULL
          AND u.is_online = TRUE
          AND u.last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
          ORDER BY u.last_seen DESC";

$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$online_users = [];
while ($row = mysqli_fetch_assoc($result)) {
    $online_users[] = [
        'username' => $row['username'],
        'profile_photo' => $row['profile_photo'],
        'last_seen' => $row['last_seen']
    ];
}

echo json_encode([
    'success' => true,
    'online_users' => $online_users,
    'count' => count($online_users)
]);
?>