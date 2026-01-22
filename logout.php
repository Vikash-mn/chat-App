<?php
session_start();
include("connection.php");

// Update user online status before destroying session
if (isset($_SESSION['username'])) {
    $username = $_SESSION['username'];
    $query = "UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
    $stmt = mysqli_prepare($conn, $query);
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
    }
}

// Clear session data
$_SESSION = array();

// Destroy session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 42000, '/');
}

// Destroy session
session_destroy();

// Clear any room-specific cookies
if (isset($_COOKIE)) {
    foreach ($_COOKIE as $name => $value) {
        if (strpos($name, 'user_token_') === 0) {
            setcookie($name, '', time() - 42000, '/');
        }
    }
}

// Redirect to welcome page
header("Location: welcome.php");
exit();
?>