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

// Get room creator
$room_creator = '';
$query = "SELECT creator FROM rooms WHERE roomname = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
if ($result && mysqli_num_rows($result) > 0) {
    $room = mysqli_fetch_assoc($result);
    $room_creator = $room['creator'];
}

// Get all members of the room
$query = "SELECT DISTINCT u.username, u.profile_photo, u.last_seen, u.is_online,
          ru.last_seen as room_joined_at,
          CASE WHEN u.username = ? THEN 'creator'
               WHEN ra.username IS NOT NULL THEN 'admin'
               ELSE 'member' END as role
          FROM users u
          INNER JOIN room_users ru ON u.username = ru.username
          LEFT JOIN room_admins ra ON u.username = ra.username AND ra.roomname = ru.roomname
          WHERE ru.roomname = ? AND ru.removed_at IS NULL
          ORDER BY u.username";

$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ss", $room_creator, $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$members = [];
while ($row = mysqli_fetch_assoc($result)) {
    $members[] = [
        'username' => $row['username'],
        'profile_photo' => $row['profile_photo'],
        'last_seen' => $row['last_seen'],
        'is_online' => (bool)$row['is_online'],
        'role' => $row['role'],
        'room_joined_at' => $row['room_joined_at']
    ];
}

echo json_encode([
    'success' => true,
    'members' => $members,
    'count' => count($members),
    'creator' => $room_creator
]);
?>