<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$roomname = $_POST['roomname'] ?? '';
$username = $_POST['username'] ?? '';

if (empty($roomname) || empty($username)) {
    echo json_encode(['error' => 'Room name and username required']);
    exit();
}

// Check if join_requests table exists first
$table_check = mysqli_query($conn, "SHOW TABLES LIKE 'join_requests'");
if (mysqli_num_rows($table_check) == 0) {
    // FIX: Free result
    if ($table_check) mysqli_free_result($table_check);
    echo json_encode(['error' => 'Join requests table does not exist. Please run create_join_requests_table.php first.']);
    exit();
}
// FIX: Free result
if ($table_check) mysqli_free_result($table_check);

// Check if user is room creator or admin
$query = "SELECT creator FROM rooms WHERE roomname = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    // FIX: Free result and close statement
    mysqli_free_result($result);
    mysqli_stmt_close($stmt);
    echo json_encode(['error' => 'Room not found']);
    exit();
}

$room = mysqli_fetch_assoc($result);
// FIX: Free result
mysqli_free_result($result);
// FIX: Close statement
mysqli_stmt_close($stmt);

$isCreator = ($room['creator'] === $_SESSION['username']);
$isAdmin = false;
if (!$isCreator) {
    $query = "SELECT 1 FROM room_admins WHERE roomname = ? AND username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $roomname, $_SESSION['username']);
    mysqli_stmt_execute($stmt);
    $adminResult = mysqli_stmt_get_result($stmt);
    $isAdmin = ($adminResult && mysqli_num_rows($adminResult) > 0);
    if ($adminResult) { mysqli_free_result($adminResult); }
    mysqli_stmt_close($stmt);
}

if (!$isCreator && !$isAdmin) {
    echo json_encode(['error' => 'Only room creator or admins can invite members']);
    exit();
}

// Check if the invited user exists
$query = "SELECT username FROM users WHERE username = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user_exists = mysqli_num_rows($result) > 0;
// FIX: Free result and close statement
mysqli_free_result($result);
mysqli_stmt_close($stmt);

if (!$user_exists) {
    echo json_encode(['error' => 'User to invite not found']);
    exit();
}


// Check if user is already in the room
$query = "SELECT id FROM room_users WHERE roomname = ? AND username = ? AND removed_at IS NULL";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ss", $roomname, $username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$is_in_room = mysqli_num_rows($result) > 0;
// FIX: Free result and close statement
mysqli_free_result($result);
mysqli_stmt_close($stmt);

if ($is_in_room) {
    echo json_encode(['error' => 'User is already in the room']);
    exit();
}

// Check if there's already a pending request for this user
$query = "SELECT id FROM join_requests WHERE roomname = ? AND username = ? AND status = 'pending'";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "ss", $roomname, $username);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$has_pending_request = mysqli_num_rows($result) > 0;
// FIX: Free result and close statement
mysqli_free_result($result);
mysqli_stmt_close($stmt);

if ($has_pending_request) {
    echo json_encode(['error' => 'Invitation already sent to this user']);
    exit();
}

// Create a join request instead of directly adding the user
$query = "INSERT INTO join_requests (roomname, username, requested_by, status, requested_at)
          VALUES (?, ?, ?, 'pending', NOW())";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "sss", $roomname, $username, $_SESSION['username']);

if (mysqli_stmt_execute($stmt)) {
    echo json_encode(['success' => true, 'message' => 'Invitation sent to ' . htmlspecialchars($username)]);
} else {
    echo json_encode(['error' => 'Failed to send invitation']);
}
// FIX: Close statement
mysqli_stmt_close($stmt);

// FIX: Close connection
if (isset($conn)) {
    mysqli_close($conn);
}
?>