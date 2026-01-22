<?php
session_start();
include("connection.php");

if (!isset($_SESSION['username'])) {
    header("Location: welcome.php");
    exit();
}

$roomname = $_GET['roomname'] ?? '';

if (empty($roomname)) {
    header("Location: index.php?error=invalid_room");
    exit();
}

// Sanitize roomname
$roomname = trim($roomname);

try {
    // Remove user from room_users table
    $query = "DELETE FROM room_users WHERE roomname = ? AND username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $roomname, $_SESSION['username']);
    
    if (mysqli_stmt_execute($stmt)) {
        // Clear the room-specific cookie
        setcookie('user_token_' . $roomname, '', time() - 3600, '/');
        
        // If user is the room creator, you might want to handle room deletion or transfer
        // For now, just remove them from the room
        $_SESSION['success'] = "You have left the room: " . htmlspecialchars($roomname);
    } else {
        $_SESSION['error'] = "Failed to leave room. Please try again.";
    }
    
    mysqli_stmt_close($stmt);
    
} catch (Exception $e) {
    error_log("Error leaving room: " . $e->getMessage());
    $_SESSION['error'] = "An error occurred while leaving the room.";
}

// Redirect back to index
header("Location: index.php");
exit();
?>