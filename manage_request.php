<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

// 1. Basic Validation
if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$request_id = $_POST['request_id'] ?? '';
$action     = $_POST['action'] ?? ''; // New parameter: 'approve' or 'deny'

if (empty($request_id) || empty($action)) {
    echo json_encode(['error' => 'Missing request ID or action']);
    exit();
}

if (!in_array($action, ['approve', 'deny'])) {
    echo json_encode(['error' => 'Invalid action']);
    exit();
}

// 2. Security Check (Verify Request & Ownership)
// Get request details AND verify the current user is the room creator
$query = "SELECT jr.*, r.creator FROM join_requests jr
          JOIN rooms r ON jr.roomname = r.roomname
          WHERE jr.id = ? AND jr.status = 'pending'";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "i", $request_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    echo json_encode(['error' => 'Request not found, already processed, or you are not the creator']);
    exit();
}

$request = mysqli_fetch_assoc($result);

if ($request['creator'] !== $_SESSION['username']) {
    echo json_encode(['error' => 'Access denied: Only the room creator can manage requests']);
    exit();
}

// 3. Process Action
if ($action === 'approve') {
    // A. Mark as approved
    $query = "UPDATE join_requests SET status = 'approved', reviewed_at = NOW(), reviewed_by = ? WHERE id = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "si", $_SESSION['username'], $request_id);
    
    if (mysqli_stmt_execute($stmt)) {
        // B. Add user to the room
        $user_token = bin2hex(random_bytes(16));
        $query = "INSERT INTO room_users (roomname, username, user_token, joined_at) VALUES (?, ?, ?, NOW())";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "sss", $request['roomname'], $request['username'], $user_token);
        
        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'message' => 'Request approved and user added']);
        } else {
            // Rollback status if adding fails (optional but recommended)
            echo json_encode(['error' => 'Request approved but failed to add user to room']);
        }
    } else {
        echo json_encode(['error' => 'Database error during approval']);
    }

} elseif ($action === 'deny') {
    // A. Mark as denied
    $query = "UPDATE join_requests SET status = 'denied', reviewed_at = NOW(), reviewed_by = ? WHERE id = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "si", $_SESSION['username'], $request_id);
    
    if (mysqli_stmt_execute($stmt)) {
        echo json_encode(['success' => true, 'message' => 'Request denied']);
    } else {
        echo json_encode(['error' => 'Database error during denial']);
    }
}
?>