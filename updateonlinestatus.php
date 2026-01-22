<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

$action = $_POST['action'] ?? $_GET['action'] ?? 'ping';

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$username = $_SESSION['username'];

switch ($action) {
    case 'offline':
        // User is leaving - mark as offline
        $query = "UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $username);

        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'status' => 'offline']);
        } else {
            echo json_encode(['error' => 'Failed to update status']);
        }
        break;

    case 'ping':
    default:
        // Update last seen timestamp and ensure user is marked as online
        $query = "UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $username);

        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'status' => 'online']);
        } else {
            echo json_encode(['error' => 'Failed to update status']);
        }
        break;
}
?>