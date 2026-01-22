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

if (!isset($_POST['settings']) || !isset($_POST['roomname'])) {
    echo json_encode(['error' => 'Missing parameters']);
    exit();
}

$roomname = $_POST['roomname'];
$username = $_SESSION['username'];
$settings_json = $_POST['settings'];

try {
    $settings = json_decode($settings_json, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON data');
    }

    // Verify user is room creator or admin
    $query = "SELECT creator FROM rooms WHERE roomname = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $roomname);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) == 0) {
        throw new Exception('Room not found');
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
            throw new Exception('Access denied. Only room creator or admins can change settings.');
        }
    }

    $success_count = 0;
    $errors = [];

    // Update room name if changed
    if (!empty($settings['name']) && $settings['name'] !== $roomname) {
        $new_name = trim($settings['name']);

        // Validate new name
        if (strlen($new_name) < 2 || strlen($new_name) > 15) {
            $errors[] = 'Room name must be between 2-15 characters';
        } elseif (!ctype_alnum($new_name)) {
            $errors[] = 'Room name can only contain letters and numbers';
        } else {
            // Check if new name already exists
            $query = "SELECT roomname FROM rooms WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "s", $new_name);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) > 0) {
                $errors[] = 'Room name already exists';
            } else {
                // Update room name
                $query = "UPDATE rooms SET roomname = ? WHERE roomname = ?";
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "ss", $new_name, $roomname);

                if (mysqli_stmt_execute($stmt)) {
                    $success_count++;
                    $old_roomname = $roomname;
                    $roomname = $new_name; // Update for subsequent operations
                } else {
                    $errors[] = 'Failed to update room name';
                }
            }
        }
    }

    // Update room description
    if (isset($settings['description'])) {
        $description = trim($settings['description']);

        $query = "UPDATE rooms SET description = ? WHERE roomname = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "ss", $description, $roomname);

        if (mysqli_stmt_execute($stmt)) {
            $success_count++;
        } else {
            $errors[] = 'Failed to update description';
        }
    }

    // Update room password if provided
    if (!empty($settings['password'])) {
        $password = $settings['password'];

        if (strlen($password) < 4) {
            $errors[] = 'Password must be at least 4 characters';
        } else {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            $query = "UPDATE rooms SET password = ? WHERE roomname = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $hashed_password, $roomname);

            if (mysqli_stmt_execute($stmt)) {
                $success_count++;
            } else {
                $errors[] = 'Failed to update password';
            }
        }
    }

    // Update room privacy settings
    $privacy_settings = [
        'privateGroup' => $settings['privateGroup'] ?? false,
        'approveMembers' => $settings['approveMembers'] ?? false,
        'allowGuest' => $settings['allowGuest'] ?? false
    ];

    // Store privacy settings as JSON in description field for now
    // (In a real application, you'd want separate columns for these)
    $current_description = '';
    $query = "SELECT description FROM rooms WHERE roomname = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $roomname);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($result && mysqli_num_rows($result) > 0) {
        $room_data = mysqli_fetch_assoc($result);
        $current_description = $room_data['description'] ?? '';
    }

    // Merge current description with privacy settings
    $privacy_json = json_encode($privacy_settings);
    $new_description = trim($current_description . "\n\n[PRIVACY_SETTINGS]" . $privacy_json);

    $query = "UPDATE rooms SET description = ? WHERE roomname = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $new_description, $roomname);

    if (mysqli_stmt_execute($stmt)) {
        $success_count++;
    } else {
        $errors[] = 'Failed to update privacy settings';
    }

    // Update notification settings for the room
    $notification_settings = [
        'notifyMessages' => $settings['notifyMessages'] ?? true,
        'notifyMentions' => $settings['notifyMentions'] ?? true,
        'notifyMedia' => $settings['notifyMedia'] ?? true,
        'muteGroup' => $settings['muteGroup'] ?? false,
        'notificationSound' => $settings['notificationSound'] ?? 'default'
    ];

    // Store in user preferences for now (room-specific preferences)
    foreach ($notification_settings as $key => $value) {
        $pref_key = "room_{$roomname}_{$key}";

        $query = "INSERT INTO user_preferences (username, preference_key, preference_value)
                  VALUES (?, ?, ?)
                  ON DUPLICATE KEY UPDATE preference_value = VALUES(preference_value)";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "sss", $username, $pref_key, (string)$value);

        if (mysqli_stmt_execute($stmt)) {
            $success_count++;
        } else {
            $errors[] = "Failed to update notification setting: $key";
        }
    }

    // Response
    if ($success_count > 0 && empty($errors)) {
        $response = ['success' => true, 'message' => 'Settings saved successfully'];

        // If room name was changed, include redirect info
        if (isset($old_roomname)) {
            $response['new_name'] = $roomname;
            $response['redirect'] = "room.php?roomname=" . urlencode($roomname);
        }

        echo json_encode($response);
    } else {
        echo json_encode([
            'success' => false,
            'error' => 'Failed to save settings',
            'details' => $errors
        ]);
    }

} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>