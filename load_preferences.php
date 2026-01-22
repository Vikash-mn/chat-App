<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$username = $_SESSION['username'];

// Check if table exists
$tableExists = mysqli_query($conn, "SHOW TABLES LIKE 'user_preferences'");
$preferences = [];

if ($tableExists && mysqli_num_rows($tableExists) > 0) {
    // Load all user preferences
    $query = "SELECT preference_key, preference_value FROM user_preferences WHERE username = ?";
    $stmt = mysqli_prepare($conn, $query);
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        while ($row = mysqli_fetch_assoc($result)) {
            $preferences[$row['preference_key']] = $row['preference_value'];
        }
        
        // FIX: Free result and close statement
        mysqli_free_result($result);
        mysqli_stmt_close($stmt);
    }
}
// FIX: Free result from SHOW TABLES
if ($tableExists) {
    mysqli_free_result($tableExists);
}

echo json_encode(['preferences' => $preferences]);

// FIX: Close connection
if (isset($conn)) {
    mysqli_close($conn);
}
?>