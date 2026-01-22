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

// Check if user is room creator
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
// FIX: Free result and close statement
mysqli_free_result($result);
mysqli_stmt_close($stmt);

if ($room['creator'] !== $_SESSION['username']) {
    echo json_encode(['error' => 'Only room creator can view requests']);
    exit();
}

// Check if table exists first
$table_check = mysqli_query($conn, "SHOW TABLES LIKE 'join_requests'");
if (mysqli_num_rows($table_check) == 0) {
    // FIX: Free result
    if ($table_check) mysqli_free_result($table_check);
    echo json_encode([
        'success' => false,
        'error' => 'Join requests table does not exist. Please run create_join_requests_table.php first.'
    ]);
    exit();
}
// FIX: Free result
if ($table_check) mysqli_free_result($table_check);

// Get pending requests for this room
$query = "SELECT jr.*, u.profile_photo FROM join_requests jr
          LEFT JOIN users u ON jr.username = u.username
          WHERE jr.roomname = ? AND jr.status = 'pending'
          ORDER BY jr.requested_at DESC";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

$requests = [];
while ($row = mysqli_fetch_assoc($result)) {
    $requests[] = $row;
}

// FIX: Free result and close statement
mysqli_free_result($result);
mysqli_stmt_close($stmt);

echo json_encode(['success' => true, 'requests' => $requests]);

// FIX: Close connection
if (isset($conn)) {
    mysqli_close($conn);
}
?>