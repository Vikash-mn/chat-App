<?php
session_start();
include("connection.php");

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Invalid request method']);
    exit();
}

if (!isset($_SESSION['username'])) {
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$action = $_POST['action'] ?? '';
$roomname = $_POST['roomname'] ?? '';
$username = $_SESSION['username'];

if (empty($action) || empty($roomname)) {
    echo json_encode(['error' => 'Missing parameters']);
    exit();
}

// Verify user is room creator or admin
$query = "SELECT creator FROM rooms WHERE roomname = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "s", $roomname);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) == 0) {
    echo json_encode(['error' => 'Room not found']);
    exit();
}

$room = mysqli_fetch_assoc($result);
if ($room['creator'] !== $username) {
    // Check if user is admin
    $query = "SELECT username FROM room_admins WHERE roomname = ? AND username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $roomname, $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) == 0) {
        echo json_encode(['error' => 'Access denied. Only room creator or admins can update settings.']);
        exit();
    }
}

switch ($action) {
    case 'update_name':
        $new_name = trim($_POST['new_name'] ?? '');

        if (empty($new_name)) {
            echo json_encode(['error' => 'New name is required']);
            exit();
        }

        // Validate new name
        if (strlen($new_name) < 2 || strlen($new_name) > 15) {
            echo json_encode(['error' => 'Room name must be between 2-15 characters']);
            exit();
        }

        if (!ctype_alnum($new_name)) {
            echo json_encode(['error' => 'Room name can only contain letters and numbers']);
            exit();
        }

        // Check if new name already exists
        $query = "SELECT roomname FROM rooms WHERE roomname = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $new_name);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);

        if (mysqli_stmt_num_rows($stmt) > 0) {
            echo json_encode(['error' => 'Room name already exists']);
            exit();
        }

        // Update room name in all related tables
        mysqli_begin_transaction($conn);

        try {
            // Update rooms table
            $query = "UPDATE rooms SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            // Update room_users table
            $query = "UPDATE room_users SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            // Update messages table
            $query = "UPDATE messages SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            // Update typing_indicators table
            $query = "UPDATE typing_indicators SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            // Update room_admins table
            $query = "UPDATE room_admins SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            // Update join_requests table
            $query = "UPDATE join_requests SET roomname = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);
            mysqli_stmt_execute($stmt);

            mysqli_commit($conn);

            echo json_encode([
                'success' => true,
                'new_name' => $new_name,
                'message' => 'Room name updated successfully'
            ]);

        } catch (Exception $e) {
            mysqli_rollback($conn);
            echo json_encode(['error' => 'Failed to update room name: ' . $e->getMessage()]);
        }

        break;

    case 'update_password':
        $new_password = $_POST['new_password'] ?? '';

        if (empty($new_password)) {
            echo json_encode(['error' => 'New password is required']);
            exit();
        }

        if (strlen($new_password) < 4) {
            echo json_encode(['error' => 'Password must be at least 4 characters']);
            exit();
        }

        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        $query = "UPDATE rooms SET password = ? WHERE roomname = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "ss", $hashed_password, $roomname);

        if (mysqli_stmt_execute($stmt)) {
            echo json_encode(['success' => true, 'message' => 'Password updated successfully']);
        } else {
            echo json_encode(['error' => 'Failed to update password']);
        }

        break;

    case 'update_display_photo':
        if (!isset($_FILES['display_photo'])) {
            echo json_encode(['error' => 'No file uploaded']);
            exit();
        }

        $file = $_FILES['display_photo'];

        // Validate file
        if ($file['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['error' => 'File upload error']);
            exit();
        }

        $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (!in_array($file['type'], $allowed_types)) {
            echo json_encode(['error' => 'Only image files (JPEG, PNG, GIF, WebP) are allowed']);
            exit();
        }

        if ($file['size'] > 5 * 1024 * 1024) { // 5MB limit
            echo json_encode(['error' => 'File size must be less than 5MB']);
            exit();
        }

        // Create uploads directory if it doesn't exist
        $upload_dir = 'uploads/room_photos/';
        if (!file_exists($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }

        // Generate unique filename
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = uniqid('room_' . $roomname . '_', true) . '.' . $extension;
        $filepath = $upload_dir . $filename;

        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            // Update database with new photo path
            $query = "UPDATE rooms SET display_photo = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $filepath, $roomname);

            if (mysqli_stmt_execute($stmt)) {
                echo json_encode([
                    'success' => true,
                    'photo_path' => $filepath,
                    'message' => 'Display photo updated successfully'
                ]);
            } else {
                // Delete uploaded file if database update failed
                unlink($filepath);
                echo json_encode(['error' => 'Failed to update photo in database']);
            }
        } else {
            echo json_encode(['error' => 'Failed to save uploaded file']);
        }

        break;

    default:
        echo json_encode(['error' => 'Invalid action']);
        break;
}
?>