<?php
session_start();
include("connection.php");

// Generate CSRF token if it doesn't exist
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['username'])) {
    header("Location: welcome.php");
    exit();
}

// Get current user info
$username = $_SESSION['username'];

// Get user profile photo (with error handling for missing column)
$profile_photo = null;
$query = "SELECT profile_photo FROM users WHERE username = ?";
$stmt = mysqli_prepare($conn, $query);
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $username);
    if (mysqli_stmt_execute($stmt)) {
        $result = mysqli_stmt_get_result($stmt);
        if ($result && mysqli_num_rows($result) > 0) {
            $user_data = mysqli_fetch_assoc($result);
            $profile_photo = $user_data['profile_photo'];
            // Validate path to prevent directory traversal
            if ($profile_photo && !preg_match('/^uploads\/avatars\/[a-zA-Z0-9_.-]+$/', $profile_photo)) {
                $profile_photo = null;
                error_log("Invalid profile photo path: " . $profile_photo);
            }
        }
    }
    mysqli_stmt_close($stmt);
}

// Helper function to show alert and redirect
function showAlertAndRedirect($message) {
    $escapedMessage = json_encode($message);
    echo "<script>alert($escapedMessage); window.location = 'index.php';</script>";
    exit();
}

// Handle AJAX requests for real-time data
if (isset($_GET['action']) || isset($_POST['action'])) {
    header('Content-Type: application/json');

    $action = $_GET['action'] ?? $_POST['action'] ?? '';

    switch ($action) {
        case 'get_rooms':
            // Get all rooms the user has access to
            $query = "SELECT DISTINCT r.roomname, r.creator, r.created_at,
                             COUNT(ru.username) as member_count,
                             MAX(m.created_at) as last_message_time
                      FROM rooms r
                      LEFT JOIN room_users ru ON r.roomname = ru.roomname
                      LEFT JOIN messages m ON r.roomname = m.roomname
                      WHERE ru.username = ? OR r.creator = ?
                      GROUP BY r.roomname, r.creator, r.created_at
                      ORDER BY last_message_time DESC, r.created_at DESC";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $_SESSION['username'], $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            $rooms = [];
            while ($row = mysqli_fetch_assoc($result)) {
                $rooms[] = [
                    'roomname' => $row['roomname'],
                    'creator' => $row['creator'],
                    'member_count' => $row['member_count'],
                    'created_at' => $row['created_at'],
                    'last_message_time' => $row['last_message_time']
                ];
            }
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'rooms' => $rooms]);
            exit();

        case 'get_online_users':
            // Get online users count
            $query = "SELECT COUNT(*) as online_count FROM users WHERE is_online = 1 AND last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)";
            $result = mysqli_query($conn, $query);
            if ($result) {
                $online_count = mysqli_fetch_assoc($result)['online_count'];
                echo json_encode(['success' => true, 'online_count' => $online_count]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to get online users']);
            }
            exit();

        case 'get_room_stats':
            // Get overall room statistics
            $stats = [];

            // Total rooms
            $result = mysqli_query($conn, "SELECT COUNT(*) as total_rooms FROM rooms");
            if ($result) {
                $stats['total_rooms'] = mysqli_fetch_assoc($result)['total_rooms'];
            }

            // Total users
            $result = mysqli_query($conn, "SELECT COUNT(*) as total_users FROM users");
            if ($result) {
                $stats['total_users'] = mysqli_fetch_assoc($result)['total_users'];
            }

            // Active users (online in last 5 minutes)
            $result = mysqli_query($conn, "SELECT COUNT(*) as active_users FROM users WHERE last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
            if ($result) {
                $stats['active_users'] = mysqli_fetch_assoc($result)['active_users'];
            }

            // Total messages
            $result = mysqli_query($conn, "SELECT COUNT(*) as total_messages FROM messages");
            if ($result) {
                $stats['total_messages'] = mysqli_fetch_assoc($result)['total_messages'];
            }

            echo json_encode(['success' => true, 'stats' => $stats]);
            exit();

        case 'get_recent_activity':
            // Get recent activity across all rooms
            $query = "SELECT
                        m.roomname,
                        m.username,
                        m.msg,
                        m.created_at,
                        r.creator
                      FROM messages m
                      JOIN rooms r ON m.roomname = r.roomname
                      WHERE m.created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
                      ORDER BY m.created_at DESC
                      LIMIT 10";
            $result = mysqli_query($conn, $query);

            $activities = [];
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $activities[] = [
                        'roomname' => $row['roomname'],
                        'username' => $row['username'],
                        'message' => substr($row['msg'], 0, 50) . (strlen($row['msg']) > 50 ? '...' : ''),
                        'created_at' => $row['created_at'],
                        'is_creator' => $row['creator'] === $row['username']
                    ];
                }
            }

            echo json_encode(['success' => true, 'activities' => $activities]);
            exit();

        case 'get_room_activity':
            // Get activity for specific rooms
            $roomnames = isset($_GET['rooms']) ? json_decode($_GET['rooms'], true) : [];
            if (empty($roomnames)) {
                echo json_encode(['success' => false, 'error' => 'No rooms specified']);
                exit();
            }

            $placeholders = str_repeat('?,', count($roomnames) - 1) . '?';
            $query = "SELECT
                        m.roomname,
                        COUNT(*) as message_count,
                        MAX(m.created_at) as last_message_time,
                        COUNT(DISTINCT ru.username) as member_count
                      FROM messages m
                      RIGHT JOIN room_users ru ON m.roomname = ru.roomname
                      WHERE m.roomname IN ($placeholders) OR ru.roomname IN ($placeholders)
                      GROUP BY m.roomname";

            $stmt = mysqli_prepare($conn, $query);
            $params = array_merge($roomnames, $roomnames);
            mysqli_stmt_bind_param($stmt, str_repeat('s', count($params)), ...$params);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            $activity = [];
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $activity[$row['roomname']] = [
                        'message_count' => $row['message_count'] ?: 0,
                        'last_message_time' => $row['last_message_time'],
                        'member_count' => $row['member_count'] ?: 0
                    ];
                }
            }
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'activity' => $activity]);
            exit();

        case 'ping':
            // Update user online status
            $query = "UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "s", $_SESSION['username']);
            if (mysqli_stmt_execute($stmt)) {
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to update status']);
            }
            mysqli_stmt_close($stmt);
            exit();

        case 'toggle_theme':
            try {
                // Toggle and save user's theme preference
                $current_theme = isset($_SESSION['dark_mode']) ? $_SESSION['dark_mode'] : false;
                $new_theme = !$current_theme;
                $_SESSION['dark_mode'] = $new_theme;

                // Check if user_preferences table exists
                $table_check = mysqli_query($conn, "SHOW TABLES LIKE 'user_preferences'");
                if (mysqli_num_rows($table_check) > 0) {
                    // Save to user preferences
                    $query = "INSERT INTO user_preferences (username, preference_key, preference_value)
                              VALUES (?, 'theme', ?)
                              ON DUPLICATE KEY UPDATE preference_value = VALUES(preference_value)";
                    $stmt = mysqli_prepare($conn, $query);
                    
                    if ($stmt) {
                        $theme_value = $new_theme ? 'dark' : 'light';
                        mysqli_stmt_bind_param($stmt, "ss", $_SESSION['username'], $theme_value);
                        
                        if (!mysqli_stmt_execute($stmt)) {
                            error_log("Theme preference save failed: " . mysqli_stmt_error($stmt));
                            // Continue anyway - we'll use session
                        }
                        mysqli_stmt_close($stmt);
                    }
                } else {
                    error_log("user_preferences table does not exist");
                    // Continue with session-only theme
                }

                echo json_encode([
                    'success' => true,
                    'dark_mode' => $new_theme,
                    'theme' => $new_theme ? 'dark' : 'light'
                ]);
                
            } catch (Exception $e) {
                error_log("Theme toggle error: " . $e->getMessage());
                // Fallback to session-only
                echo json_encode([
                    'success' => true, // Still return success for UX
                    'dark_mode' => $new_theme,
                    'theme' => $new_theme ? 'dark' : 'light',
                    'note' => 'Theme saved to session only'
                ]);
            }
            exit();

        case 'get_user_theme':
            try {
                $theme = 'light'; // Default
                
                // First check session
                if (isset($_SESSION['dark_mode'])) {
                    $theme = $_SESSION['dark_mode'] ? 'dark' : 'light';
                } else {
                    // Check if table exists
                    $table_check = mysqli_query($conn, "SHOW TABLES LIKE 'user_preferences'");
                    if (mysqli_num_rows($table_check) > 0) {
                        // Get user's theme preference from database
                        $query = "SELECT preference_value FROM user_preferences
                                  WHERE username = ? AND preference_key = 'theme'";
                        $stmt = mysqli_prepare($conn, $query);
                        
                        if ($stmt) {
                            mysqli_stmt_bind_param($stmt, "s", $_SESSION['username']);
                            if (mysqli_stmt_execute($stmt)) {
                                $result = mysqli_stmt_get_result($stmt);
                                $row = mysqli_fetch_assoc($result);
                                if ($row) {
                                    $theme = $row['preference_value'];
                                    // Update session
                                    $_SESSION['dark_mode'] = $theme === 'dark';
                                }
                            }
                            mysqli_stmt_close($stmt);
                        }
                    }
                }

                echo json_encode([
                    'success' => true,
                    'theme' => $theme
                ]);
                
            } catch (Exception $e) {
                error_log("Get user theme error: " . $e->getMessage());
                // Fallback
                $theme = isset($_SESSION['dark_mode']) && $_SESSION['dark_mode'] ? 'dark' : 'light';
                echo json_encode([
                    'success' => true,
                    'theme' => $theme
                ]);
            }
            exit();

        case 'search_friends':
            $email = trim($_GET['email'] ?? '');
            if (empty($email)) {
                echo json_encode(['success' => false, 'error' => 'Email is required']);
                exit();
            }

            $query = "SELECT username, email, profile_photo, is_online, last_seen FROM users
                       WHERE (email LIKE ? OR username LIKE ?) AND username != ?";
            $stmt = mysqli_prepare($conn, $query);
            $search_term = "%$email%";
            mysqli_stmt_bind_param($stmt, "sss", $search_term, $search_term, $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            $users = [];
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $users[] = $row;
                }
            }
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'users' => $users]);
            exit();

        case 'send_friend_request':
            $friend_username = trim($_POST['friend_username'] ?? '');
            if (empty($friend_username)) {
                echo json_encode(['success' => false, 'error' => 'Friend username is required']);
                exit();
            }

            // Check if user exists
            $query = "SELECT username FROM users WHERE username = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "s", $friend_username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if (mysqli_num_rows($result) == 0) {
                mysqli_stmt_close($stmt);
                echo json_encode(['success' => false, 'error' => 'User not found']);
                exit();
            }

            $friend_data = mysqli_fetch_assoc($result);
            $actual_friend_username = $friend_data['username'];
            $current_username = $_SESSION['username'];
            mysqli_stmt_close($stmt);

            // Check if already friends or request exists
            $query = "SELECT status FROM friend_requests 
                      WHERE (sender_username = ? AND receiver_username = ?) 
                         OR (sender_username = ? AND receiver_username = ?)";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ssss", $current_username, $actual_friend_username, $actual_friend_username, $current_username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if (mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                mysqli_stmt_close($stmt);
                if ($row['status'] == 'accepted') {
                    echo json_encode(['success' => false, 'error' => 'Already friends']);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Friend request already exists']);
                }
                exit();
            }
            mysqli_stmt_close($stmt);

            // Send friend request
            $query = "INSERT INTO friend_requests (sender_username, receiver_username, status) VALUES (?, ?, 'pending')";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $current_username, $actual_friend_username);

            if (mysqli_stmt_execute($stmt)) {
                echo json_encode(['success' => true, 'message' => 'Friend request sent']);
            } else {
                error_log("Friend request insert error: " . mysqli_error($conn));
                echo json_encode(['success' => false, 'error' => 'Database error: ' . mysqli_error($conn)]);
            }
            mysqli_stmt_close($stmt);
            exit();

        case 'get_friend_requests':
            $query = "SELECT fr.id, fr.sender_username, fr.created_at, u.email, u.profile_photo, u.is_online
                      FROM friend_requests fr
                      JOIN users u ON fr.sender_username = u.username
                      WHERE fr.receiver_username = ? AND fr.status = 'pending'
                      ORDER BY fr.created_at DESC";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "s", $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            $requests = [];
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $requests[] = $row;
                }
            }
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'requests' => $requests]);
            exit();

        case 'respond_friend_request':
            $request_id = intval($_POST['request_id'] ?? 0);
            $action = $_POST['action'] ?? '';

            if (!$request_id || !in_array($action, ['accept', 'decline'])) {
                echo json_encode(['success' => false, 'error' => 'Invalid request']);
                exit();
            }

            // Verify request belongs to user
            $query = "SELECT sender_username FROM friend_requests
                      WHERE id = ? AND receiver_username = ? AND status = 'pending'";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "is", $request_id, $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if (mysqli_num_rows($result) == 0) {
                mysqli_stmt_close($stmt);
                echo json_encode(['success' => false, 'error' => 'Request not found']);
                exit();
            }

            $row = mysqli_fetch_assoc($result);
            $friend_username = $row['sender_username'];
            mysqli_stmt_close($stmt);

            if ($action == 'accept') {
                // Update request status
                $query = "UPDATE friend_requests SET status = 'accepted' WHERE id = ?";
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "i", $request_id);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);

                // Add to friends table
                $query = "INSERT INTO friends (user1, user2) VALUES (?, ?)";
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "ss", $_SESSION['username'], $friend_username);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);

                echo json_encode(['success' => true, 'message' => 'Friend request accepted']);
            } else {
                // Update request status to declined
                $query = "UPDATE friend_requests SET status = 'declined' WHERE id = ?";
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "i", $request_id);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);

                echo json_encode(['success' => true, 'message' => 'Friend request declined']);
            }
            exit();

        case 'get_friends':
            $query = "SELECT u.username, u.email, u.profile_photo, u.is_online, u.last_seen,
                             (SELECT COUNT(*) FROM personal_messages pm 
                              WHERE ((pm.from_user = ? AND pm.to_user = u.username) 
                                 OR (pm.from_user = u.username AND pm.to_user = ?))
                              AND pm.is_read = 0 AND pm.to_user = ?) as unread_count
                      FROM friends f
                      JOIN users u ON (f.user1 = u.username OR f.user2 = u.username)
                      WHERE (f.user1 = ? OR f.user2 = ?) AND u.username != ?
                      ORDER BY u.is_online DESC, u.last_seen DESC";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ssssss", $_SESSION['username'], $_SESSION['username'], $_SESSION['username'], $_SESSION['username'], $_SESSION['username'], $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            $friends = [];
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $friends[] = $row;
                }
            }
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'friends' => $friends]);
            exit();

        case 'get_personal_messages':
            $with_user = trim($_GET['with_user'] ?? '');
            $last_message_id = intval($_GET['last_message_id'] ?? 0);
            
            if (empty($with_user)) {
                echo json_encode(['success' => false, 'error' => 'User not specified']);
                exit();
            }

            try {
                // Check if they are friends
                $friend_check_query = "
                    SELECT 1 FROM friends 
                    WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)
                ";
                $friend_check_stmt = mysqli_prepare($conn, $friend_check_query);
                mysqli_stmt_bind_param($friend_check_stmt, "ssss", $_SESSION['username'], $with_user, $with_user, $_SESSION['username']);
                mysqli_stmt_execute($friend_check_stmt);
                $friend_result = mysqli_stmt_get_result($friend_check_stmt);

                if (mysqli_num_rows($friend_result) == 0) {
                    mysqli_stmt_close($friend_check_stmt);
                    echo json_encode(['success' => false, 'error' => 'You can only message friends']);
                    exit();
                }
                mysqli_stmt_close($friend_check_stmt);

                // Mark messages as read
                $mark_read_query = "UPDATE personal_messages SET is_read = 1 
                                   WHERE from_user = ? AND to_user = ? AND is_read = 0";
                $mark_read_stmt = mysqli_prepare($conn, $mark_read_query);
                mysqli_stmt_bind_param($mark_read_stmt, "ss", $with_user, $_SESSION['username']);
                mysqli_stmt_execute($mark_read_stmt);
                mysqli_stmt_close($mark_read_stmt);

                // Get messages
                if ($last_message_id > 0) {
                    $query = "SELECT pm.id, pm.from_user, pm.to_user, pm.message, pm.message_type, 
                                     pm.file_path, pm.file_size, pm.created_at, pm.is_read, pm.is_deleted
                              FROM personal_messages pm
                              WHERE ((pm.from_user = ? AND pm.to_user = ?) OR (pm.from_user = ? AND pm.to_user = ?))
                              AND pm.id > ? AND (pm.is_deleted = 0 OR (pm.is_deleted = 1 AND pm.from_user = ?))
                              ORDER BY pm.created_at ASC";
                    $stmt = mysqli_prepare($conn, $query);
                    mysqli_stmt_bind_param($stmt, "ssssis", $_SESSION['username'], $with_user, $with_user, $_SESSION['username'], $last_message_id, $_SESSION['username']);
                } else {
                    $query = "SELECT pm.id, pm.from_user, pm.to_user, pm.message, pm.message_type, 
                                     pm.file_path, pm.file_size, pm.created_at, pm.is_read, pm.is_deleted
                              FROM personal_messages pm
                              WHERE ((pm.from_user = ? AND pm.to_user = ?) OR (pm.from_user = ? AND pm.to_user = ?))
                              AND (pm.is_deleted = 0 OR (pm.is_deleted = 1 AND pm.from_user = ?))
                              ORDER BY pm.created_at DESC
                              LIMIT 50";
                    $stmt = mysqli_prepare($conn, $query);
                    mysqli_stmt_bind_param($stmt, "sssss", $_SESSION['username'], $with_user, $with_user, $_SESSION['username'], $_SESSION['username']);
                }
                
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);

                $messages = [];
                if ($result) {
                    while ($row = mysqli_fetch_assoc($result)) {
                        $messages[] = $row;
                    }
                }
                mysqli_stmt_close($stmt);

                // Reverse for correct chronological order if loading all messages
                if ($last_message_id == 0) {
                    $messages = array_reverse($messages);
                }

                echo json_encode(['success' => true, 'messages' => $messages]);
                
            } catch (Exception $e) {
                error_log("Error getting personal messages: " . $e->getMessage());
                echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
            }
            exit();

        case 'delete_message':
            $message_id = intval($_POST['message_id'] ?? 0);
            $delete_type = $_POST['delete_type'] ?? 'for_me'; // for_me or for_everyone

            if (!$message_id) {
                echo json_encode(['success' => false, 'error' => 'Invalid message']);
                exit();
            }

            // Verify user owns the message
            $verify_query = "SELECT from_user FROM personal_messages WHERE id = ?";
            $verify_stmt = mysqli_prepare($conn, $verify_query);
            mysqli_stmt_bind_param($verify_stmt, "i", $message_id);
            mysqli_stmt_execute($verify_stmt);
            $verify_result = mysqli_stmt_get_result($verify_stmt);

            if (mysqli_num_rows($verify_result) == 0) {
                mysqli_stmt_close($verify_stmt);
                echo json_encode(['success' => false, 'error' => 'Message not found']);
                exit();
            }

            $message_data = mysqli_fetch_assoc($verify_result);
            mysqli_stmt_close($verify_stmt);
            
            if ($message_data['from_user'] !== $_SESSION['username']) {
                echo json_encode(['success' => false, 'error' => 'You can only delete your own messages']);
                exit();
            }

            if ($delete_type === 'for_everyone') {
                // Delete for everyone
                $delete_query = "DELETE FROM personal_messages WHERE id = ?";
            } else {
                // Delete for me only (soft delete)
                $delete_query = "UPDATE personal_messages SET is_deleted = 1 WHERE id = ?";
            }

            $delete_stmt = mysqli_prepare($conn, $delete_query);
            mysqli_stmt_bind_param($delete_stmt, "i", $message_id);

            if (mysqli_stmt_execute($delete_stmt)) {
                echo json_encode(['success' => true, 'message' => 'Message deleted']);
            } else {
                echo json_encode(['success' => false, 'error' => 'Failed to delete message']);
            }
            mysqli_stmt_close($delete_stmt);
            exit();

        case 'get_unread_count':
            $query = "SELECT COUNT(*) as unread_count FROM personal_messages 
                      WHERE to_user = ? AND is_read = 0";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "s", $_SESSION['username']);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $unread_data = mysqli_fetch_assoc($result);
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true, 'unread_count' => $unread_data['unread_count']]);
            exit();

        case 'typing_status':
            $to_user = trim($_POST['to_user'] ?? '');
            $is_typing = intval($_POST['is_typing'] ?? 0);

            if (empty($to_user)) {
                echo json_encode(['success' => false, 'error' => 'User not specified']);
                exit();
            }

            // Store typing status in database for personal messaging
            $query = "INSERT INTO personal_typing_status (from_user, to_user, is_typing, last_updated)
                      VALUES (?, ?, ?, NOW())
                      ON DUPLICATE KEY UPDATE is_typing = VALUES(is_typing), last_updated = NOW()";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ssi", $_SESSION['username'], $to_user, $is_typing);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            echo json_encode(['success' => true]);
            exit();

        case 'get_typing_status':
            $from_user = trim($_GET['from_user'] ?? '');

            if (empty($from_user)) {
                echo json_encode(['success' => false, 'error' => 'User not specified']);
                exit();
            }

            try {
                // Check if personal_typing_status table exists
                $table_check = mysqli_query($conn, "SHOW TABLES LIKE 'personal_typing_status'");
                if (mysqli_num_rows($table_check) == 0) {
                    // Create personal_typing_status table for personal messaging
                    $create_table = "CREATE TABLE personal_typing_status (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        from_user VARCHAR(50) NOT NULL,
                        to_user VARCHAR(50) NOT NULL,
                        is_typing BOOLEAN NOT NULL DEFAULT 0,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY unique_personal_typing (from_user, to_user),
                        INDEX idx_from_user (from_user),
                        INDEX idx_to_user (to_user)
                    )";
                    mysqli_query($conn, $create_table);
                    echo json_encode(['success' => true, 'is_typing' => 0]);
                    exit();
                }

                $query = "SELECT is_typing FROM personal_typing_status
                          WHERE from_user = ? AND to_user = ? AND last_updated > DATE_SUB(NOW(), INTERVAL 3 SECOND)";
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "ss", $from_user, $_SESSION['username']);
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);
                $typing_data = mysqli_fetch_assoc($result);
                mysqli_stmt_close($stmt);

                echo json_encode(['success' => true, 'is_typing' => $typing_data ? (int)$typing_data['is_typing'] : 0]);

            } catch (Exception $e) {
                error_log("Error getting typing status: " . $e->getMessage());
                echo json_encode(['success' => true, 'is_typing' => 0]); // Default to not typing on error
            }
            exit();

        default:
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
            exit();
    }
}

// Handle form submissions for room creation and joining
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['create_room'])) {
        $username = $_POST['username'];
        $roomname = $_POST['room'];
        $password = $_POST['password'];
        $repassword = $_POST['repassword'];

        // Validate inputs
        if (empty($username) || empty($roomname) || empty($password)) {
            showAlertAndRedirect("All fields are required.");
        }

        if ($password !== $repassword) {
            showAlertAndRedirect("Passwords do not match.");
        }

        if (strlen($roomname) < 2 || strlen($roomname) > 15) {
            showAlertAndRedirect("Room name must be between 2-15 characters.");
        }

        if (!ctype_alnum($roomname)) {
            showAlertAndRedirect("Room name can only contain letters and numbers.");
        }

        if (strlen($password) < 4) {
            showAlertAndRedirect("Password must be at least 4 characters.");
        }

        // Use prepared statements for all database operations
        $checkQuery = "SELECT roomname FROM rooms WHERE roomname = ?";
        $checkStmt = mysqli_prepare($conn, $checkQuery);
        mysqli_stmt_bind_param($checkStmt, "s", $roomname);
        mysqli_stmt_execute($checkStmt);
        mysqli_stmt_store_result($checkStmt);

        if (mysqli_stmt_num_rows($checkStmt) > 0) {
            mysqli_stmt_close($checkStmt);
            showAlertAndRedirect("Room name already exists. Please choose a different name.");
        }
        mysqli_stmt_close($checkStmt);

        // Create room with creator field
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $creator = $_SESSION['username']; // Get creator from session

        $query = "INSERT INTO rooms (roomname, password, creator) VALUES (?, ?, ?)";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "sss", $roomname, $hashed_password, $creator);

        if (mysqli_stmt_execute($stmt)) {
            mysqli_stmt_close($stmt);
            
            // Store user information
            $user_token = bin2hex(random_bytes(16));
            $query = "INSERT INTO room_users (roomname, username, user_token) VALUES (?, ?, ?)";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "sss", $roomname, $username, $user_token);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
            
            $_SESSION['username'] = $username;
            setcookie('user_token_'.$roomname, $user_token, time() + (30 * 24 * 60 * 60), '/');
            header("Location: room.php?roomname=" . urlencode($roomname));
            exit();
        } else {
            mysqli_stmt_close($stmt);
            showAlertAndRedirect("Error creating room. Please try again.");
        }
    } elseif (isset($_POST['join_room'])) {
        $roomname = trim($_POST['room']);
        $password = $_POST['password'];

        // Basic validation
        if (empty($roomname) || empty($password)) {
            showAlertAndRedirect("Both room name and password are required.");
        }

        // Get room details
        $query = "SELECT password FROM rooms WHERE roomname = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $roomname);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        if (mysqli_num_rows($result) == 0) {
            mysqli_stmt_close($stmt);
            showAlertAndRedirect("Room does not exist. Please check the room name.");
        }

        $room = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);
        
        // Verify password
        if (!password_verify($password, $room['password'])) {
            showAlertAndRedirect("Incorrect password for this room.");
        }

        // Set user session and cookies
        $username = $_SESSION['username'] ?? 'Guest_'.bin2hex(random_bytes(4));
        $user_token = bin2hex(random_bytes(16));
        
        // Store user-room association
        $query = "INSERT INTO room_users (roomname, username, user_token) VALUES (?, ?, ?) 
                  ON DUPLICATE KEY UPDATE user_token = VALUES(user_token)";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "sss", $roomname, $username, $user_token);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);

        // Set session and cookie
        $_SESSION['username'] = $username;
        setcookie('user_token_'.$roomname, $user_token, time() + (86400 * 30), "/"); // 30 days
        
        // Redirect to room
        header("Location: room.php?roomname=".urlencode($roomname));
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Galaxy Chat - Personal & Rooms</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ===== CSS VARIABLES ===== */
        :root {
            /* Light Theme */
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-tertiary: #e9ecef;
            --bg-overlay: rgba(0, 0, 0, 0.5);
            
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --text-muted: #adb5bd;
            --text-light: #ffffff;
            
            --border-color: #dee2e6;
            --border-light: #f1f3f4;
            --border-dark: #ced4da;
            
            --accent-primary: #007bff;
            --accent-primary-hover: #0056b3;
            --accent-secondary: #6c757d;
            --accent-success: #28a745;
            --accent-danger: #dc3545;
            --accent-warning: #ffc107;
            --accent-info: #17a2b8;
            --accent-purple: #6f42c1;
            --accent-pink: #e83e8c;
            
            --shadow-sm: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            --shadow-md: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
            --shadow-lg: 0 1rem 3rem rgba(0, 0, 0, 0.175);
            --shadow-inset: inset 0 1px 2px rgba(0, 0, 0, 0.075);
            
            --border-radius: 0.375rem;
            --border-radius-sm: 0.25rem;
            --border-radius-lg: 0.5rem;
            --border-radius-xl: 1rem;
            --border-radius-pill: 50rem;
            
            --font-family-sans-serif: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-family-monospace: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            
            --transition: all 0.3s ease;
            --transition-fast: all 0.15s ease;
            --transition-slow: all 0.5s ease;
            
            --z-index-dropdown: 1000;
            --z-index-sticky: 1020;
            --z-index-fixed: 1030;
            --z-index-modal: 1040;
            --z-index-popover: 1050;
            --z-index-tooltip: 1060;
            --z-index-toast: 1070;
            
            --sidebar-width: 320px;
            --chat-width: 400px;
        }

        [data-theme="dark"] {
            --bg-primary: #121212;
            --bg-secondary: #1e1e1e;
            --bg-tertiary: #2d2d2d;
            --bg-overlay: rgba(0, 0, 0, 0.7);
            
            --text-primary: #e9ecef;
            --text-secondary: #adb5bd;
            --text-muted: #6c757d;
            --text-light: #f8f9fa;
            
            --border-color: #444;
            --border-light: #555;
            --border-dark: #333;
            
            --accent-primary: #0d6efd;
            --accent-primary-hover: #0b5ed7;
            --accent-secondary: #5a6268;
            --accent-success: #198754;
            --accent-danger: #dc3545;
            --accent-warning: #ffc107;
            --accent-info: #0dcaf0;
            --accent-purple: #6f42c1;
            --accent-pink: #e83e8c;
            
            --shadow-sm: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.4);
            --shadow-md: 0 0.5rem 1rem rgba(0, 0, 0, 0.5);
            --shadow-lg: 0 1rem 3rem rgba(0, 0, 0, 0.6);
            --shadow-inset: inset 0 1px 2px rgba(0, 0, 0, 0.4);
        }

        /* ===== RESET AND BASE STYLES ===== */
        *, *::before, *::after {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        html {
            font-size: 16px;
            scroll-behavior: smooth;
        }

        body {
            font-family: var(--font-family-sans-serif);
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
            transition: var(--transition);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }

        /* ===== MAIN LAYOUT ===== */
        .app-container {
            display: flex;
            height: 100vh;
            background: var(--bg-primary);
        }

        /* Sidebar */
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            transition: var(--transition);
            z-index: var(--z-index-fixed);
        }

        .sidebar-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .sidebar-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
        }

        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }

        .sidebar-section {
            margin-bottom: 1.5rem;
        }

        .sidebar-section:last-child {
            margin-bottom: 0;
        }

        .sidebar-section h3 {
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Chat Area */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-primary);
            position: relative;
        }

        .chat-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .chat-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
        }

        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background: var(--bg-primary);
        }

        .message-input-container {
            padding: 1rem 1.5rem;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border-color);
            position: relative;
        }

        /* Rooms Area */
        .rooms-area {
            width: var(--chat-width);
            background: var(--bg-secondary);
            border-left: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            transition: var(--transition);
        }

        .rooms-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }

        .rooms-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
        }

        .rooms-content {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }

        /* ===== COMPONENTS ===== */
        /* User List */
        .user-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .user-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: var(--border-radius);
            transition: var(--transition);
            border: 1px solid transparent;
            cursor: pointer;
        }

        .user-item:hover {
            background: var(--bg-tertiary);
            border-color: var(--border-light);
        }

        .user-item.active {
            background: var(--accent-primary);
            color: white;
        }

        .user-avatar {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-purple));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 0.875rem;
            position: relative;
            flex-shrink: 0;
        }

        .online-status {
            position: absolute;
            bottom: 0;
            right: 0;
            width: 0.75rem;
            height: 0.75rem;
            border-radius: 50%;
            background: var(--accent-success);
            border: 2px solid var(--bg-secondary);
            transition: var(--transition);
        }

        .user-item.offline .online-status {
            background: var(--accent-secondary);
        }

        .user-info {
            flex: 1;
            min-width: 0;
        }

        .user-name {
            font-weight: 500;
            color: inherit;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 0.125rem;
        }

        .user-status {
            font-size: 0.75rem;
            color: inherit;
            opacity: 0.8;
        }

        /* Message Styles */
        .message {
            max-width: 70%;
            padding: 0.75rem 1rem;
            border-radius: var(--border-radius-xl);
            position: relative;
            animation: messageSlideIn 0.3s ease;
            box-shadow: var(--shadow-sm);
            word-wrap: break-word;
        }

        @keyframes messageSlideIn {
            from {
                opacity: 0;
                transform: translateY(1rem) scale(0.95);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        .message-incoming {
            align-self: flex-start;
            background: var(--bg-secondary);
            border-bottom-left-radius: var(--border-radius);
        }

        .message-outgoing {
            align-self: flex-end;
            background: var(--accent-primary);
            color: white;
            border-bottom-right-radius: var(--border-radius);
        }

        .message-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.25rem;
        }

        .message-sender {
            font-weight: 600;
            font-size: 0.875rem;
        }

        .message-time {
            font-size: 0.75rem;
            opacity: 0.7;
        }

        .message-content {
            line-height: 1.4;
            white-space: pre-wrap;
        }

        /* Message Input */
        .message-form {
            display: flex;
            gap: 0.75rem;
            align-items: flex-end;
        }

        .message-input-wrapper {
            flex: 1;
            position: relative;
        }

        .message-input {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius-xl);
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.875rem;
            resize: none;
            max-height: 120px;
            min-height: 44px;
            transition: var(--transition);
            font-family: inherit;
        }

        .message-input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }

        .send-button {
            padding: 0.75rem;
            background: var(--accent-primary);
            color: white;
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 44px;
            min-height: 44px;
        }

        .send-button:hover:not(:disabled) {
            background: var(--accent-primary-hover);
            transform: translateY(-1px);
        }

        .send-button:disabled {
            background: var(--accent-secondary);
            cursor: not-allowed;
            transform: none;
        }

        /* Room Forms */
        .form-container {
            display: none;
            flex-direction: column;
            gap: 1rem;
            margin-top: 1rem;
        }

        .form-container.active {
            display: flex;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .input-group {
            position: relative;
        }

        .form-container input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: var(--transition);
        }

        .form-container input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }

        .form-container button[type="submit"] {
            padding: 0.75rem;
            background: var(--accent-primary);
            border: none;
            border-radius: var(--border-radius);
            color: white;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
        }

        .form-container button[type="submit"]:hover {
            background: var(--accent-primary-hover);
        }

        /* Toggle Buttons */
        .toggle-buttons {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .toggle-buttons button {
            flex: 1;
            padding: 0.5rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
        }

        .toggle-buttons button:hover {
            background: var(--border-color);
        }

        .toggle-buttons button.active {
            background: var(--accent-primary);
            color: white;
            border-color: var(--accent-primary);
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--border-radius);
            font-size: 0.875rem;
            font-weight: 500;
            line-height: 1.5;
            text-decoration: none;
            cursor: pointer;
            transition: var(--transition);
            user-select: none;
        }

        .btn-primary {
            background: var(--accent-primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--accent-primary-hover);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--border-color);
        }

        .btn-icon {
            padding: 0.5rem;
            width: 2.5rem;
            height: 2.5rem;
        }

        /* Empty States */
        .empty-state {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* ===== RESPONSIVE DESIGN ===== */
        @media (max-width: 1024px) {
            :root {
                --sidebar-width: 280px;
                --chat-width: 350px;
            }
        }

        @media (max-width: 768px) {
            .rooms-area {
                position: fixed;
                right: -100%;
                top: 0;
                height: 100%;
                z-index: var(--z-index-modal);
                width: 100%;
                max-width: 400px;
                box-shadow: var(--shadow-lg);
            }

            .rooms-area.show {
                right: 0;
            }

            .message {
                max-width: 85%;
            }
        }

        @media (max-width: 576px) {
            .sidebar {
                position: fixed;
                left: -100%;
                top: 0;
                height: 100%;
                z-index: var(--z-index-modal);
                width: 100%;
                max-width: 320px;
                box-shadow: var(--shadow-lg);
            }

            .sidebar.show {
                left: 0;
            }

            .messages-container {
                padding: 1rem;
            }

            .message-input-container {
                padding: 0.75rem 1rem;
            }

            .message {
                max-width: 95%;
                padding: 0.5rem 0.75rem;
            }
        }

        /* ===== UTILITY CLASSES ===== */
        .hidden {
            display: none !important;
        }

        .text-center {
            text-align: center;
        }

        .text-muted {
            color: var(--text-muted);
        }

        .d-flex {
            display: flex;
        }

        .justify-content-between {
            justify-content: space-between;
        }

        .align-items-center {
            align-items: center;
        }

        .w-100 {
            width: 100%;
        }

        .p-3 {
            padding: 1rem;
        }

        .mb-3 {
            margin-bottom: 1rem;
        }

        .rounded {
            border-radius: var(--border-radius);
        }

        .shadow {
            box-shadow: var(--shadow-sm);
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar - Users List -->
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <h2>Chats</h2>
                <button class="btn btn-icon btn-secondary" onclick="toggleSidebar()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="sidebar-content">
                <div class="sidebar-section">
                    <h3>Find Friends</h3>
                    <div class="input-group" style="margin-bottom: 1rem;">
                        <input type="email" id="friend-search" placeholder="Search by email..." style="width: 100%; padding: 0.5rem; border: 1px solid var(--border-color); border-radius: var(--border-radius); background: var(--bg-primary); color: var(--text-primary);">
                        <button onclick="searchFriends()" style="margin-top: 0.5rem; width: 100%; padding: 0.5rem; background: var(--accent-primary); color: white; border: none; border-radius: var(--border-radius); cursor: pointer;">Search</button>
                    </div>
                    <div id="friend-search-results" class="user-list">
                        <!-- Friend search results will appear here -->
                    </div>
                </div>

                <div class="sidebar-section">
                    <h3>Friend Requests</h3>
                    <div id="friend-requests-list" class="user-list">
                        <!-- Friend requests will be loaded here -->
                        <div class="text-center p-2">
                            <div class="skeleton" style="height: 16px; width: 100px; margin: 0 auto;"></div>
                        </div>
                    </div>
                </div>

                <div class="sidebar-section">
                    <h3>My Friends</h3>
                    <div class="user-list" id="friends-list">
                        <!-- Friends will be loaded here -->
                        <div class="text-center p-2">
                            <div class="skeleton" style="height: 16px; width: 80px; margin: 0 auto;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </aside>

        <!-- Main Chat Area -->
        <main class="chat-area">
            <div class="chat-header">
                <div class="d-flex align-items-center">
                    <button class="btn btn-icon btn-secondary mr-2" onclick="toggleSidebar()">
                        <i class="fas fa-bars"></i>
                    </button>
                    <h2 id="chat-with-user">Select a user to chat</h2>
                </div>
                <div class="d-flex align-items-center">
                    <button class="btn btn-info btn-icon" onclick="openScanModal()" title="Scan QR Code">
                        <i class="fas fa-camera"></i>
                    </button>
                    <button class="btn btn-icon btn-secondary ml-2" onclick="toggleTheme()">
                        <i class="fas fa-moon"></i>
                    </button>
                    <button class="btn btn-icon btn-secondary ml-2" onclick="toggleRooms()">
                        <i class="fas fa-comments"></i>
                    </button>
                    <button class="btn btn-icon btn-secondary ml-2" onclick="logout()" title="Logout">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>

            <div class="messages-container" id="messages-container">
                <div class="empty-state">
                    <i class="fas fa-comments"></i>
                    <h3>Welcome to Galaxy Chat</h3>
                    <p>Create or join a chat room to start messaging</p>
                </div>
            </div>

            <div class="message-input-container">
                <form class="message-form" id="message-form">
                    <div class="message-input-wrapper">
                        <textarea 
                            class="message-input" 
                            id="message-input" 
                            placeholder="Type a message..." 
                            rows="1"
                            disabled
                        ></textarea>
                    </div>
                    <button type="submit" class="send-button" id="send-button" disabled>
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </form>
            </div>
        </main>

        <!-- Rooms Area -->
        <aside class="rooms-area" id="rooms-area">
            <div class="rooms-header">
                <h2>Chat Rooms</h2>
                <button class="btn btn-icon btn-secondary" onclick="toggleRooms()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="rooms-content">
                <div class="toggle-buttons">
                    <button class="active" onclick="showForm('create')">Create Room</button>
                    <button onclick="showForm('join')">Join Room</button>
                </div>
                
                <form id="createForm" class="form-container active" method="POST" action="index.php">
    <input type="hidden" name="create_room" value="1">
    <div class="input-group">
        <input type="text" id="username" name="username"
                value="<?php echo htmlspecialchars($_SESSION['username']); ?>" 
                readonly
                autocomplete="username">
    </div>
    <div class="input-group">
        <input type="text" id="room" name="room" 
               placeholder="Room Name" 
               required 
               maxlength="15" 
               pattern="[a-zA-Z0-9_\- ]+" 
               title="Only letters, numbers, spaces, hyphens and underscores allowed"
               autocomplete="off">
    </div>
    <div class="input-group">
        <input type="password" id="password" name="password" 
               placeholder="Password" 
               required 
               minlength="4"
               autocomplete="new-password">
    </div>
    <div class="input-group">
        <input type="password" id="repassword" name="repassword" 
               placeholder="Confirm Password" 
               required
               autocomplete="new-password">
    </div>
    <button type="submit">Create Room</button>
</form>
                
                <form id="joinForm" class="form-container" method="POST" action="index.php">
    <input type="hidden" name="join_room" value="1">
    <div class="input-group">
        <input type="text" id="join_room" name="room" 
               placeholder="Room Name" 
               required 
               maxlength="15" 
               pattern="[a-zA-Z0-9_\- ]+" 
               title="Only letters, numbers, spaces, hyphens and underscores allowed"
               autocomplete="off">
    </div>
    <div class="input-group">
        <input type="password" id="join_password" name="password" 
               placeholder="Password" 
               required
               autocomplete="current-password">
    </div>
    <button type="submit">Join Room</button>
</form>

                <div class="sidebar-section mt-4">
                    <h3>Your Rooms</h3>
                    <div class="user-list" id="user-rooms-list">
                        <!-- Rooms will be loaded dynamically -->
                        <div class="text-center p-3">
                            <div class="skeleton" style="height: 20px; width: 120px; margin: 0 auto 10px;"></div>
                            <div class="skeleton" style="height: 16px; width: 80px; margin: 0 auto;"></div>
                        </div>
                    </div>
                </div>

                <div class="sidebar-section">
                    <h3>Platform Stats</h3>
                    <div id="platform-stats">
                        <div class="text-center p-2">
                            <div class="skeleton" style="height: 16px; width: 100px; margin: 0 auto 5px;"></div>
                            <div class="skeleton" style="height: 16px; width: 80px; margin: 0 auto;"></div>
                        </div>
                    </div>
                </div>

                <div class="sidebar-section">
                    <h3>Recent Activity</h3>
                    <div id="recent-activity">
                        <div class="text-center p-2">
                            <div class="skeleton" style="height: 16px; width: 120px; margin: 0 auto 5px;"></div>
                            <div class="skeleton" style="height: 14px; width: 90px; margin: 0 auto;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </aside>
    </div>

    <!-- Notification Container -->
    <div id="notification-container" style="position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;"></div>

    <!-- Scan QR Code Modal -->
    <div class="modal" id="scan-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 500px;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-camera"></i> Scan QR Code</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeScanModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="text-center">
                    <p class="mb-3">Upload a QR code image to join a room</p>
                    <div class="form-group">
                        <label class="form-label" for="qr-file">Select QR Code Image</label>
                        <input type="file" class="form-control" id="qr-file" accept="image/*" onchange="handleFileSelect(event)">
                        <div class="form-text">Supported formats: PNG, JPG, JPEG, GIF</div>
                    </div>
                    <div id="scan-result" class="mt-3" style="display: none;">
                        <div class="alert alert-info">
                            <i class="fas fa-spinner fa-spin"></i> Processing QR code...
                        </div>
                    </div>
                    <div id="scan-preview" class="mt-3" style="display: none;">
                        <img id="preview-image" class="img-fluid" style="max-width: 200px; max-height: 200px;" alt="QR Code Preview">
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeScanModal()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="processQRCode()" id="process-btn" disabled>
                    <i class="fas fa-search"></i> Process QR Code
                </button>
            </div>
        </div>
    </div>
<script>
    // Enhanced personal chat system
    const personalChat = {
        currentChatUser: null,
        messages: new Map(),
        typingTimeouts: new Map(),
        isScrolledToBottom: true,
        lastMessageId: 0,
        messagePollingInterval: null,
        typingPollingInterval: null,
        
        // Initialize personal chat
        init() {
            this.setupEventListeners();
            this.startMessagePolling();
            this.startTypingPolling();
            this.loadUnreadCount();
        },

        // Setup enhanced event listeners
setupEventListeners() {
    try {
        // Message input events - check if elements exist first
        const messageInput = document.getElementById('message-input');
        const messageForm = document.getElementById('message-form');
        const messagesContainer = document.getElementById('messages-container');

        if (messageInput) {
            messageInput.addEventListener('input', this.handleTyping.bind(this));
            messageInput.addEventListener('keydown', this.handleKeyDown.bind(this));
            messageInput.addEventListener('paste', this.handlePaste.bind(this));
        }

        if (messageForm) {
            messageForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.sendMessage();
            });
        }

        if (messagesContainer) {
            // Scroll events for infinite scroll
            messagesContainer.addEventListener('scroll', this.handleScroll.bind(this));

            // Drag and drop for file sharing
            messagesContainer.addEventListener('dragover', this.handleDragOver.bind(this));
            messagesContainer.addEventListener('drop', this.handleFileDrop.bind(this));

            // Context menu for messages
            messagesContainer.addEventListener('contextmenu', this.handleContextMenu.bind(this));
        }
    } catch (error) {
        console.error('Error setting up event listeners:', error);
    }
},
// Add these methods to the personalChat object (place them before the init method):

// Handle scroll for infinite loading (stub - implement as needed)
handleScroll(e) {
    // Implementation for infinite scroll
    const container = e.target;
    if (container.scrollTop === 0) {
        // Load more messages when scrolled to top
        if (this.currentChatUser) {
            this.loadMessages(this.currentChatUser.username, true);
        }
    }
},

// Handle context menu (stub)
handleContextMenu(e) {
    e.preventDefault();
    // Context menu implementation would go here
},

// Show message menu (stub)
showMessageMenu(event) {
    event.stopPropagation();
    // Implementation for showing message menu
},

// Copy message (stub)
copyMessage(messageElement) {
    const messageContent = messageElement.querySelector('.message-content').textContent;
    navigator.clipboard.writeText(messageContent).then(() => {
        queueNotification('Message copied to clipboard', 'success');
    });
},

// Edit message (stub)
editMessage(messageElement) {
    // Implementation for editing messages
    queueNotification('Edit feature coming soon', 'info');
},

// Show user profile (stub)
showUserProfile() {
    if (this.currentChatUser) {
        queueNotification(`Viewing profile of ${this.currentChatUser.username}`, 'info');
    }
},

// Toggle media view (stub)
toggleMediaView() {
    queueNotification('Media view coming soon', 'info');
},

// Search in chat (stub)
searchInChat() {
    queueNotification('Chat search coming soon', 'info');
},

// Clear chat (stub)
clearChat() {
    if (this.currentChatUser && confirm('Clear all messages in this chat?')) {
        queueNotification('Clear chat feature coming soon', 'info');
    }
},

// Enlarge image (stub)
enlargeImage(imageSrc) {
    // Implementation for image modal
    queueNotification('Image viewer coming soon', 'info');
},

// Download file (stub)
downloadFile(filePath) {
    // Implementation for file download
    queueNotification('Download feature coming soon', 'info');
},

// Prepend messages for infinite scroll (stub)
prependMessages(messages) {
    // Implementation for adding messages at the top
    console.log('Prepending messages:', messages);
},
        // Select user to chat with
        async selectUser(user) {
            this.currentChatUser = user;
            
            // Update UI
            document.getElementById('chat-with-user').textContent = user.username;
            document.getElementById('message-input').disabled = false;
            document.getElementById('message-input').placeholder = `Message ${user.username}...`;
            document.getElementById('message-input').focus();

            // Update active states
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('active');
            });
            document.querySelectorAll(`[data-username="${user.username}"]`).forEach(item => {
                item.classList.add('active');
            });

            // Show chat interface
            this.showChatInterface();
            
            // Load messages
            await this.loadMessages(user.username);
            
            // On mobile, close sidebar
            if (window.innerWidth <= 576) {
                toggleSidebar();
            }
        },

        // Show enhanced chat interface
        showChatInterface() {
            const container = document.getElementById('messages-container');
            container.innerHTML = `
                <div class="chat-header-info">
                    <div class="user-info-large">
                        <div class="user-avatar large">
                            ${this.currentChatUser.username.charAt(0).toUpperCase()}
                            <div class="online-status ${this.currentChatUser.is_online ? '' : 'offline'}"></div>
                        </div>
                        <div class="user-details">
                            <div class="user-name">${this.currentChatUser.username}</div>
                            <div class="user-status" id="typing-indicator"></div>
                        </div>
                    </div>
                    <div class="chat-actions">
                        <button class="btn btn-icon" onclick="personalChat.showUserProfile()" title="Profile">
                            <i class="fas fa-user"></i>
                        </button>
                        <button class="btn btn-icon" onclick="personalChat.toggleMediaView()" title="Media">
                            <i class="fas fa-images"></i>
                        </button>
                        <button class="btn btn-icon" onclick="personalChat.searchInChat()" title="Search">
                            <i class="fas fa-search"></i>
                        </button>
                        <button class="btn btn-icon" onclick="personalChat.clearChat()" title="Clear Chat">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
                <div class="messages-list" id="messages-list"></div>
            `;
        },

        // Load messages with pagination
        async loadMessages(username, loadMore = false) {
            try {
                const url = `index.php?action=get_personal_messages&with_user=${encodeURIComponent(username)}${loadMore ? `&last_message_id=${this.lastMessageId}` : ''}`;
                const response = await fetch(url);
                const data = await response.json();

                if (data.success) {
                    if (loadMore) {
                        this.prependMessages(data.messages);
                    } else {
                        this.displayMessages(data.messages);
                    }
                    
                    // Update last message ID
                    if (data.messages.length > 0) {
                        this.lastMessageId = data.messages[data.messages.length - 1].id;
                    }
                }
            } catch (error) {
                console.error('Error loading messages:', error);
            }
        },

        // Display messages with enhanced features
        displayMessages(messages) {
            const container = document.getElementById('messages-list');
            if (!container) return;

            if (messages.length === 0) {
                container.innerHTML = `
                    <div class="empty-chat-state">
                        <i class="fas fa-comments"></i>
                        <h3>No messages yet</h3>
                        <p>Start a conversation with ${this.currentChatUser.username}</p>
                        <div class="chat-starter-actions">
                            <button class="btn btn-primary" onclick="personalChat.sendStarterMessage('Hi! 👋')">
                                Say Hi
                            </button>
                            <button class="btn btn-secondary" onclick="personalChat.sendStarterMessage('How are you?')">
                                Ask How They Are
                            </button>
                        </div>
                    </div>
                `;
                return;
            }

            container.innerHTML = '';
            messages.forEach(message => {
                const messageElement = this.createMessageElement(message);
                container.appendChild(messageElement);
            });

            this.scrollToBottom();
        },

        // Create enhanced message element
        createMessageElement(message) {
            const isOutgoing = message.from_user === '<?php echo $_SESSION['username']; ?>';
            const messageDiv = document.createElement('div');
            const timestamp = this.formatMessageTime(message.created_at);
            const isDeleted = message.is_deleted;
            
            messageDiv.className = `message ${isOutgoing ? 'message-outgoing' : 'message-incoming'} ${isDeleted ? 'message-deleted' : ''}`;
            messageDiv.setAttribute('data-message-id', message.id);
            messageDiv.setAttribute('data-timestamp', message.created_at);

            if (isDeleted) {
                messageDiv.innerHTML = `
                    <div class="message-content deleted">
                        <i class="fas fa-trash"></i> This message was deleted
                    </div>
                    <div class="message-time">${timestamp}</div>
                `;
            } else if (message.message_type === 'image') {
                messageDiv.innerHTML = `
                    <div class="message-content">
                        <div class="message-image">
                            <img src="${message.file_path}" alt="Shared image" onclick="personalChat.enlargeImage('${message.file_path}')">
                            <div class="image-actions">
                                <button class="btn btn-icon btn-sm" onclick="personalChat.downloadFile('${message.file_path}')">
                                    <i class="fas fa-download"></i>
                                </button>
                            </div>
                        </div>
                        ${message.message ? `<div class="image-caption">${this.escapeHtml(message.message)}</div>` : ''}
                    </div>
                    <div class="message-time">${timestamp}</div>
                    ${isOutgoing ? this.getMessageActions() : ''}
                `;
            } else if (message.message_type === 'file') {
                messageDiv.innerHTML = `
                    <div class="message-content">
                        <div class="file-message">
                            <i class="fas fa-file ${this.getFileIcon(message.file_path)}"></i>
                            <div class="file-info">
                                <div class="file-name">${this.getFileName(message.file_path)}</div>
                                <div class="file-size">${this.formatFileSize(message.file_size)}</div>
                            </div>
                            <button class="btn btn-primary btn-sm" onclick="personalChat.downloadFile('${message.file_path}')">
                                Download
                            </button>
                        </div>
                        ${message.message ? `<div class="file-description">${this.escapeHtml(message.message)}</div>` : ''}
                    </div>
                    <div class="message-time">${timestamp}</div>
                    ${isOutgoing ? this.getMessageActions() : ''}
                `;
            } else {
                messageDiv.innerHTML = `
                    <div class="message-content">${this.formatMessageText(message.message)}</div>
                    <div class="message-time">${timestamp}</div>
                    <div class="message-status">
                        ${isOutgoing ? (message.is_read ? '<i class="fas fa-check-double read"></i>' : '<i class="fas fa-check sent"></i>') : ''}
                    </div>
                    ${isOutgoing ? this.getMessageActions() : ''}
                `;
            }

            // Add double-click to reply
            if (!isDeleted) {
                messageDiv.addEventListener('dblclick', () => {
                    this.replyToMessage(message);
                });
            }

            return messageDiv;
        },

        // Format message text with emoji and links
        formatMessageText(text) {
            if (!text) return '';
            
            // Convert emoji shortcodes
            text = this.convertEmojis(text);
            
            // Convert URLs to links
            text = this.convertUrls(text);
            
            // Convert newlines to breaks
            text = text.replace(/\n/g, '<br>');
            
            return this.escapeHtml(text);
        },

        // Convert emoji shortcodes
        convertEmojis(text) {
            const emojiMap = {
                ':)': '😊',
                ':(': '😔',
                ':D': '😃',
                ';)': '😉',
                ':P': '😛',
                ':O': '😮',
                ':*': '😘',
                '<3': '❤️',
                ':thumbsup:': '👍',
                ':thumbsdown:': '👎',
                ':fire:': '🔥',
                ':100:': '💯'
            };
            
            return text.replace(/:\)|:\(|:D|;\)|:P|:O|:\*|<3|:thumbsup:|:thumbsdown:|:fire:|:100:/g, match => emojiMap[match] || match);
        },

        // Convert URLs to clickable links
        convertUrls(text) {
            const urlRegex = /(https?:\/\/[^\s]+)/g;
            return text.replace(urlRegex, '<a href="$1" target="_blank" rel="noopener">$1</a>');
        },

        // Get message actions menu
        getMessageActions() {
            return `
                <div class="message-actions">
                    <button class="btn btn-icon btn-sm" onclick="personalChat.showMessageMenu(event)">
                        <i class="fas fa-ellipsis-v"></i>
                    </button>
                    <div class="message-menu">
                        <button onclick="personalChat.replyToMessage(this.closest('.message'))">Reply</button>
                        <button onclick="personalChat.copyMessage(this.closest('.message'))">Copy</button>
                        <button onclick="personalChat.editMessage(this.closest('.message'))">Edit</button>
                        <button class="delete-btn" onclick="personalChat.deleteMessage(this.closest('.message'), 'for_me')">Delete for Me</button>
                        <button class="delete-btn" onclick="personalChat.deleteMessage(this.closest('.message'), 'for_everyone')">Delete for Everyone</button>
                    </div>
                </div>
            `;
        },

        // Send message with enhanced features
        async sendMessage() {
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();

            if (!message || !this.currentChatUser) return;

            // Clear typing status
            this.setTypingStatus(false);

            // Disable input during send
            messageInput.disabled = true;
            document.getElementById('send-button').disabled = true;

            try {
                const formData = new FormData();
                formData.append('action', 'send_personal_message');
                formData.append('to_user', this.currentChatUser.username);
                formData.append('message', message);
                formData.append('message_type', 'text');

                const response = await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    messageInput.value = '';
                    messageInput.style.height = 'auto';
                    
                    // Add message to UI immediately
                    if (data.message_data) {
                        this.addMessageToUI(data.message_data);
                    }
                } else {
                    queueNotification('Failed to send message: ' + (data.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                console.error('Error sending message:', error);
                queueNotification('Error sending message. Please try again.', 'error');
            } finally {
                messageInput.disabled = false;
                document.getElementById('send-button').disabled = messageInput.value.trim() === '';
                messageInput.focus();
            }
        },

        // Add message to UI immediately (for real-time updates)
        addMessageToUI(messageData) {
            const container = document.getElementById('messages-list');
            if (!container) return;

            // Remove empty state if it exists
            const emptyState = container.querySelector('.empty-chat-state');
            if (emptyState) {
                emptyState.remove();
            }

            const messageElement = this.createMessageElement(messageData);
            container.appendChild(messageElement);
            
            this.scrollToBottom();
        },

        // Handle typing indicator
        handleTyping() {
            if (!this.currentChatUser) return;

            // Clear existing timeout
            if (this.typingTimeouts.has(this.currentChatUser.username)) {
                clearTimeout(this.typingTimeouts.get(this.currentChatUser.username));
            }

            // Set typing status
            this.setTypingStatus(true);

            // Set timeout to clear typing status
            const timeout = setTimeout(() => {
                this.setTypingStatus(false);
            }, 1000);

            this.typingTimeouts.set(this.currentChatUser.username, timeout);
        },

        // Set typing status
        async setTypingStatus(isTyping) {
            if (!this.currentChatUser) return;

            try {
                const formData = new FormData();
                formData.append('action', 'typing_status');
                formData.append('to_user', this.currentChatUser.username);
                formData.append('is_typing', isTyping ? 1 : 0);

                await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });
            } catch (error) {
                console.error('Error setting typing status:', error);
            }
        },

        // Handle key down events for shortcuts
        handleKeyDown(e) {
            // Ctrl+Enter to send
            if (e.ctrlKey && e.key === 'Enter') {
                this.sendMessage();
                e.preventDefault();
            }
            
            // Escape to clear input
            if (e.key === 'Escape') {
                document.getElementById('message-input').value = '';
            }
        },

        // Handle file paste
        handlePaste(e) {
            const items = e.clipboardData?.items;
            if (!items) return;

            for (let item of items) {
                if (item.type.indexOf('image') !== -1) {
                    const file = item.getAsFile();
                    this.uploadFile(file);
                    break;
                }
            }
        },

        // Handle drag over for file drop
        handleDragOver(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'copy';
        },

        // Handle file drop
        handleFileDrop(e) {
            e.preventDefault();
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.uploadFile(files[0]);
            }
        },

        // Upload file
        async uploadFile(file) {
            if (!this.currentChatUser) return;

            const formData = new FormData();
            formData.append('file', file);
            formData.append('to_user', this.currentChatUser.username);

            try {
                const response = await fetch('upload_chat_file.php', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    // Send file message
                    const messageFormData = new FormData();
                    messageFormData.append('action', 'send_personal_message');
                    messageFormData.append('to_user', this.currentChatUser.username);
                    messageFormData.append('message', '');
                    messageFormData.append('message_type', data.file_type);
                    messageFormData.append('file_path', data.file_path);

                    await fetch('index.php', {
                        method: 'POST',
                        body: messageFormData
                    });

                    queueNotification('File sent successfully', 'success');
                }
            } catch (error) {
                console.error('Error uploading file:', error);
                queueNotification('Error uploading file', 'error');
            }
        },

        // Start message polling for real-time updates
        startMessagePolling() {
            this.messagePollingInterval = setInterval(() => {
                if (this.currentChatUser) {
                    this.loadNewMessages();
                }
                this.loadUnreadCount();
            }, 2000); // Poll every 2 seconds
        },

        // Start typing status polling
        startTypingPolling() {
            this.typingPollingInterval = setInterval(() => {
                if (this.currentChatUser) {
                    this.checkTypingStatus();
                }
            }, 1000); // Poll every second
        },

        // Load new messages only
        async loadNewMessages() {
            try {
                const response = await fetch(`index.php?action=get_personal_messages&with_user=${encodeURIComponent(this.currentChatUser.username)}&last_message_id=${this.lastMessageId}`);
                const data = await response.json();

                if (data.success && data.messages.length > 0) {
                    data.messages.forEach(message => {
                        this.addMessageToUI(message);
                        this.lastMessageId = Math.max(this.lastMessageId, message.id);
                    });
                }
            } catch (error) {
                console.error('Error loading new messages:', error);
            }
        },

        // Check typing status
        async checkTypingStatus() {
            try {
                const response = await fetch(`index.php?action=get_typing_status&from_user=${encodeURIComponent(this.currentChatUser.username)}`);
                const data = await response.json();

                if (data.success) {
                    this.showTypingIndicator(data.is_typing);
                }
            } catch (error) {
                console.error('Error checking typing status:', error);
            }
        },

        // Show typing indicator
        showTypingIndicator(isTyping) {
            const indicator = document.getElementById('typing-indicator');
            if (indicator) {
                indicator.textContent = isTyping ? 'typing...' : this.currentChatUser.is_online ? 'online' : 'offline';
                indicator.className = `user-status ${isTyping ? 'typing' : ''}`;
            }
        },

        // Load unread message count
        async loadUnreadCount() {
            try {
                const response = await fetch('index.php?action=get_unread_count');
                const data = await response.json();

                if (data.success) {
                    this.updateUnreadBadge(data.unread_count);
                }
            } catch (error) {
                console.error('Error loading unread count:', error);
            }
        },

        // Update unread badge
        updateUnreadBadge(count) {
            let badge = document.querySelector('.unread-badge');
            if (!badge && count > 0) {
                badge = document.createElement('div');
                badge.className = 'unread-badge';
                document.querySelector('.sidebar-header h2').appendChild(badge);
            }

            if (badge) {
                badge.textContent = count > 99 ? '99+' : count;
                badge.style.display = count > 0 ? 'flex' : 'none';
            }
        },

        // Reply to message
        replyToMessage(messageElement) {
            const messageId = messageElement.getAttribute('data-message-id');
            const messageContent = messageElement.querySelector('.message-content').textContent;
            
            const replyContainer = document.getElementById('reply-container') || this.createReplyContainer();
            replyContainer.innerHTML = `
                <div class="reply-preview">
                    <div class="reply-info">Replying to message</div>
                    <div class="reply-content">${messageContent.substring(0, 50)}${messageContent.length > 50 ? '...' : ''}</div>
                    <button class="btn btn-icon btn-sm" onclick="personalChat.cancelReply()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            replyContainer.setAttribute('data-reply-to', messageId);
            
            document.getElementById('message-input').focus();
        },

        // Create reply container
        createReplyContainer() {
            const container = document.createElement('div');
            container.id = 'reply-container';
            container.className = 'reply-container';
            document.querySelector('.message-input-container').prepend(container);
            return container;
        },

        // Cancel reply
        cancelReply() {
            const replyContainer = document.getElementById('reply-container');
            if (replyContainer) {
                replyContainer.remove();
            }
        },

        // Delete message
        async deleteMessage(messageElement, deleteType) {
            const messageId = messageElement.getAttribute('data-message-id');
            
            if (!confirm(`Are you sure you want to delete this message ${deleteType === 'for_everyone' ? 'for everyone' : 'for you'}?`)) {
                return;
            }

            try {
                const formData = new FormData();
                formData.append('action', 'delete_message');
                formData.append('message_id', messageId);
                formData.append('delete_type', deleteType);

                const response = await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    if (deleteType === 'for_everyone') {
                        messageElement.classList.add('message-deleted');
                        messageElement.querySelector('.message-content').innerHTML = '<i class="fas fa-trash"></i> This message was deleted';
                    } else {
                        messageElement.remove();
                    }
                    queueNotification('Message deleted', 'success');
                } else {
                    queueNotification(data.error, 'error');
                }
            } catch (error) {
                console.error('Error deleting message:', error);
                queueNotification('Error deleting message', 'error');
            }
        },

        // Send starter message
        sendStarterMessage(message) {
            document.getElementById('message-input').value = message;
            this.sendMessage();
        },

        // Scroll to bottom
        scrollToBottom() {
            const container = document.getElementById('messages-list');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
        },

        // Utility functions
        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        formatMessageTime(timestamp) {
            const now = new Date();
            const time = new Date(timestamp);
            const diff = Math.floor((now - time) / 1000);

            if (diff < 60) return 'Just now';
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
            return time.toLocaleDateString();
        },

        getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const iconMap = {
                'pdf': 'fa-file-pdf',
                'doc': 'fa-file-word',
                'docx': 'fa-file-word',
                'xls': 'fa-file-excel',
                'xlsx': 'fa-file-excel',
                'ppt': 'fa-file-powerpoint',
                'pptx': 'fa-file-powerpoint',
                'zip': 'fa-file-archive',
                'rar': 'fa-file-archive',
                'txt': 'fa-file-alt',
                'mp3': 'fa-file-audio',
                'wav': 'fa-file-audio',
                'mp4': 'fa-file-video',
                'avi': 'fa-file-video'
            };
            return iconMap[ext] || 'fa-file';
        },

        getFileName(path) {
            return path.split('/').pop();
        },

        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
    };

    // Initialize personal chat when DOM is loaded
    document.addEventListener('DOMContentLoaded', function() {
        personalChat.init();
        
        // Update the selectUser function to use personalChat
        window.selectUser = function(user) {
            personalChat.selectUser(user);
        };
    });

    // Enhanced CSS for personal chat features
    const enhancedChatStyles = `
        .chat-header-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }

        .user-info-large {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-avatar.large {
            width: 3rem;
            height: 3rem;
            font-size: 1.2rem;
        }

        .user-details .user-name {
            font-weight: 600;
            font-size: 1.1rem;
        }

        .user-status.typing {
            color: var(--accent-primary);
            font-style: italic;
        }

        .chat-actions {
            display: flex;
            gap: 0.5rem;
        }

        .messages-list {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .empty-chat-state {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--text-muted);
        }

        .chat-starter-actions {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            margin-top: 1rem;
        }

        .message {
            position: relative;
            transition: all 0.3s ease;
        }

        .message:hover .message-actions {
            opacity: 1;
        }

        .message-actions {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            opacity: 0;
            transition: opacity 0.3s ease;
            background: var(--bg-primary);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-md);
            padding: 0.25rem;
        }

        .message-menu {
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-lg);
            z-index: 1000;
            min-width: 150px;
        }

        .message-menu button {
            display: block;
            width: 100%;
            padding: 0.5rem 1rem;
            border: none;
            background: none;
            text-align: left;
            cursor: pointer;
            color: var(--text-primary);
            transition: background-color 0.3s ease;
        }

        .message-menu button:hover {
            background: var(--bg-tertiary);
        }

        .message-menu .delete-btn {
            color: var(--accent-danger);
        }

        .message-actions:hover .message-menu {
            display: block;
        }

        .message-image {
            position: relative;
            max-width: 300px;
            border-radius: var(--border-radius);
            overflow: hidden;
        }

        .message-image img {
            width: 100%;
            height: auto;
            cursor: zoom-in;
            transition: transform 0.3s ease;
        }

        .message-image img:hover {
            transform: scale(1.05);
        }

        .image-actions {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .message-image:hover .image-actions {
            opacity: 1;
        }

        .image-caption, .file-description {
            margin-top: 0.5rem;
            padding: 0.5rem;
            background: var(--bg-tertiary);
            border-radius: var(--border-radius);
            font-size: 0.875rem;
        }

        .file-message {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-tertiary);
            border-radius: var(--border-radius);
            border: 1px solid var(--border-color);
        }

        .file-message .fa-file {
            font-size: 2rem;
            color: var(--accent-primary);
        }

        .file-info {
            flex: 1;
        }

        .file-name {
            font-weight: 500;
            margin-bottom: 0.25rem;
        }

        .file-size {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .message-status {
            position: absolute;
            bottom: 0.25rem;
            right: 0.5rem;
            font-size: 0.75rem;
        }

        .message-status .read {
            color: var(--accent-primary);
        }

        .message-status .sent {
            color: var(--text-muted);
        }

        .message-deleted .message-content {
            opacity: 0.6;
            font-style: italic;
        }

        .reply-container {
            padding: 0.5rem;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
        }

        .reply-preview {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
        }

        .reply-info {
            color: var(--accent-primary);
            font-weight: 500;
        }

        .reply-content {
            flex: 1;
            color: var(--text-muted);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .unread-badge {
            position: absolute;
            top: -5px;
            right: -5px;
            background: var(--accent-danger);
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Image modal for enlarged view */
        .image-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--bg-overlay);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }

        .image-modal.show {
            opacity: 1;
            visibility: visible;
        }

        .image-modal-content {
            max-width: 90%;
            max-height: 90%;
            position: relative;
        }

        .image-modal-content img {
            max-width: 100%;
            max-height: 100%;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-lg);
        }

        .image-modal-close {
            position: absolute;
            top: -2rem;
            right: -2rem;
            background: var(--bg-primary);
            border: none;
            color: var(--text-primary);
            width: 2rem;
            height: 2rem;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            .chat-header-info {
                padding: 0.75rem;
            }

            .user-avatar.large {
                width: 2.5rem;
                height: 2.5rem;
            }

            .message-image {
                max-width: 250px;
            }

            .file-message {
                padding: 0.75rem;
            }
        }

        @media (max-width: 576px) {
            .chat-starter-actions {
                flex-direction: column;
            }

            .message-image {
                max-width: 200px;
            }
        }
    `;

    // Add enhanced styles to document
    const styleSheet = document.createElement('style');
    styleSheet.textContent = enhancedChatStyles;
    document.head.appendChild(styleSheet);
</script>
    <script>
        // Initialize empty data structures for room-based chat
        const users = [];
        const messages = {};

        let darkMode = false;
        let currentChatUser = null;

        // Real-time data management
        let dataPollingInterval = null;
        const POLLING_INTERVAL = 10000; // 10 seconds
        // Load new messages only
async function loadNewMessages() {
    if (!this.currentChatUser) return;
    
    try {
        const response = await fetch(`index.php?action=get_personal_messages&with_user=${encodeURIComponent(this.currentChatUser.username)}&last_message_id=${this.lastMessageId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const text = await response.text();
        if (!text) {
            throw new Error('Empty response from server');
        }
        
        const data = JSON.parse(text);

        if (data.success && data.messages.length > 0) {
            data.messages.forEach(message => {
                this.addMessageToUI(message);
                this.lastMessageId = Math.max(this.lastMessageId, message.id);
            });
        }
    } catch (error) {
        console.error('Error loading new messages:', error);
        // Don't show notification for polling errors to avoid spam
    }
}

// Check typing status
async function checkTypingStatus() {
    if (!this.currentChatUser) return;
    
    try {
        const response = await fetch(`index.php?action=get_typing_status&from_user=${encodeURIComponent(this.currentChatUser.username)}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const text = await response.text();
        if (!text) {
            throw new Error('Empty response from server');
        }
        
        const data = JSON.parse(text);

        if (data.success) {
            this.showTypingIndicator(data.is_typing);
        }
    } catch (error) {
        console.error('Error checking typing status:', error);
        // Don't show notification for polling errors
    }
}
// Start enhanced polling with different intervals for different data
function startEnhancedPolling() {
    // Fast polling for critical data (online status, activity, friends, personal messages)
    fastPollingInterval = setInterval(() => {
        loadOnlineUsersCount();
        loadRecentActivity();
        loadFriendsData();
        sendPing();
        // Check for new personal messages if chatting with someone
        if (currentChatUser) {
            loadMessages(currentChatUser.username);
        }
    }, 5000); // Increased to 5 seconds

    // Slow polling for less critical data (rooms, stats)
    slowPollingInterval = setInterval(() => {
        loadUserRooms();
        loadPlatformStats();
        // Add activity indicators after updates
        setTimeout(addActivityIndicators, 500);
    }, 15000); // Increased to 15 seconds
}
        // Initialize the app
        document.addEventListener('DOMContentLoaded', async function() {
            // Load user theme first
            await loadUserTheme();

            loadFriendsData();
            setupEventListeners();
            loadRealTimeData();

            // Enable message input for personal messaging
            document.getElementById('message-input').disabled = false;
            document.getElementById('send-button').disabled = true; // Will be enabled when typing

            // Start enhanced polling for real-time updates
            startEnhancedPolling();
        });

        // Load real-time data from server
        async function loadRealTimeData() {
            try {
                await Promise.all([
                    loadUserRooms(),
                    loadPlatformStats(),
                    loadOnlineUsersCount(),
                    loadRecentActivity(),
                    sendPing()
                ]);
            } catch (error) {
                console.error('Error loading real-time data:', error);
            }
        }

        // Load user's rooms
        async function loadUserRooms() {
            try {
                const response = await fetch('index.php?action=get_rooms');
                const data = await response.json();

                if (data.success) {
                    const previousCount = document.querySelectorAll('.room-item').length;
                    const newCount = data.rooms.length;

                    displayUserRooms(data.rooms);

                    // Show notification for new rooms
                    if (newCount > previousCount && previousCount > 0) {
                        queueNotification(`You have access to ${newCount - previousCount} new room${newCount - previousCount > 1 ? 's' : ''}`, 'success');
                    }
                }
            } catch (error) {
                console.error('Error loading user rooms:', error);
                queueNotification('Failed to load your rooms', 'warning');
            }
        }

        // Load platform statistics
        async function loadPlatformStats() {
            try {
                const response = await fetch('index.php?action=get_room_stats');
                const data = await response.json();

                if (data.success) {
                    displayPlatformStats(data.stats);
                }
            } catch (error) {
                console.error('Error loading platform stats:', error);
            }
        }

        // Load online users count
        async function loadOnlineUsersCount() {
            try {
                const response = await fetch('index.php?action=get_online_users');
                const data = await response.json();

                if (data.success) {
                    // Update online count in platform stats
                    updateOnlineCount(data.online_count);
                }
            } catch (error) {
                console.error('Error loading online users count:', error);
            }
        }

        // Load recent activity
        async function loadRecentActivity() {
            try {
                const response = await fetch('index.php?action=get_recent_activity');
                const data = await response.json();

                if (data.success) {
                    const previousCount = document.querySelectorAll('.activity-item').length;
                    const newCount = data.activities.length;

                    displayRecentActivity(data.activities);

                    // Show notification for new activities
                    if (newCount > previousCount && previousCount > 0) {
                        queueNotification(`New activity in ${newCount - previousCount} room${newCount - previousCount > 1 ? 's' : ''}`, 'info');
                    }
                }
            } catch (error) {
                console.error('Error loading recent activity:', error);
                queueNotification('Failed to load recent activity', 'warning');
            }
        }

        // Send ping to update online status
        async function sendPing() {
            try {
                await fetch('index.php?action=ping', { method: 'GET' });
            } catch (error) {
                console.error('Error sending ping:', error);
            }
        }

        // Display user rooms in the sidebar
        function displayUserRooms(rooms) {
            const container = document.getElementById('user-rooms-list');

            if (rooms.length === 0) {
                container.innerHTML = '<div class="text-muted text-center p-3">No rooms yet<br><small>Create or join a room to get started</small></div>';
                return;
            }

            let html = '';
            rooms.forEach(room => {
                const isCreator = room.creator === '<?php echo $_SESSION['username']; ?>';
                const lastActivity = room.last_message_time ?
                    formatTimeAgo(room.last_message_time) : 'No activity';

                // Add activity indicator for recently active rooms
                const isRecentlyActive = room.last_message_time &&
                    (new Date() - new Date(room.last_message_time)) < 300000; // 5 minutes

                html += `
                    <div class="user-item room-item live-update" onclick="joinRoom('${room.roomname}')" style="position: relative;">
                        <div class="user-avatar">
                            <i class="fas fa-users"></i>
                            ${isCreator ? '<span class="badge badge-primary" style="position: absolute; top: -5px; right: -5px; font-size: 0.6rem;">Owner</span>' : ''}
                            ${isRecentlyActive ? '<div class="activity-indicator" style="position: absolute; bottom: -2px; right: -2px; width: 8px; height: 8px; background: var(--accent-success); border-radius: 50%; animation: blink 2s infinite; border: 2px solid var(--bg-secondary);"></div>' : ''}
                        </div>
                        <div class="user-info">
                            <div class="user-name">${room.roomname}</div>
                            <div class="user-status">${room.member_count} members • ${lastActivity}</div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
            markAsUpdated('user-rooms-list');
        }

        // Display platform statistics
        function displayPlatformStats(stats) {
            const container = document.getElementById('platform-stats');

            container.innerHTML = `
                <div class="text-muted small">
                    <div><i class="fas fa-users"></i> ${stats.total_users} total users</div>
                    <div><i class="fas fa-comments"></i> ${stats.total_messages} messages</div>
                    <div><i class="fas fa-home"></i> ${stats.total_rooms} rooms</div>
                    <div id="online-count-display"><i class="fas fa-circle text-success"></i> ${stats.active_users} online now</div>
                </div>
            `;
        }

        // Update online count separately
        function updateOnlineCount(count) {
            const onlineDisplay = document.getElementById('online-count-display');
            if (onlineDisplay) {
                const oldCount = onlineDisplay.textContent.match(/\d+/)?.[0] || '0';
                const newCount = count.toString();

                onlineDisplay.innerHTML = `<i class="fas fa-circle text-success"></i> ${count} online now`;

                // Add visual feedback for count changes
                if (oldCount !== newCount) {
                    onlineDisplay.style.animation = 'none';
                    setTimeout(() => {
                        onlineDisplay.style.animation = 'pulse 3s infinite';
                        markAsUpdated('online-count-display');
                    }, 10);
                }
            }
        }

        // Display recent activity
        function displayRecentActivity(activities) {
            const container = document.getElementById('recent-activity');

            if (activities.length === 0) {
                container.innerHTML = '<div class="text-muted small text-center p-2">No recent activity</div>';
                return;
            }

            let html = '';
            activities.slice(0, 5).forEach(activity => { // Show only last 5 activities
                const timeAgo = formatTimeAgo(activity.created_at);
                const creatorBadge = activity.is_creator ? ' <small class="badge badge-primary">Creator</small>' : '';

                html += `
                    <div class="activity-item small mb-2 p-2 live-update" style="border-left: 3px solid var(--accent-primary); background: var(--bg-tertiary); border-radius: var(--border-radius); position: relative;">
                        <div class="activity-indicator" style="position: absolute; left: -8px; top: 50%; transform: translateY(-50%); width: 6px; height: 6px; background: var(--accent-success); border-radius: 50%; animation: blink 2s infinite;"></div>
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="flex-grow-1">
                                <strong>${activity.username}</strong>${creatorBadge} in <em>${activity.roomname}</em>
                                <div class="text-muted mt-1">${activity.message}</div>
                            </div>
                            <small class="text-muted ml-2">${timeAgo}</small>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
            markAsUpdated('recent-activity');
        }

        // Format time ago
        function formatTimeAgo(timestamp) {
            const now = new Date();
            const time = new Date(timestamp);
            const diff = Math.floor((now - time) / 1000);

            if (diff < 60) return 'Just now';
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        }

        // Join a room (redirect to room.php)
        function joinRoom(roomname) {
            // Show loading state
            queueNotification(`Joining ${roomname}...`, 'info');

            // Check if user has a token for this room
            const cookieName = 'user_token_' + roomname;
            const token = getCookie(cookieName);

            if (token) {
                // User has access, redirect to room
                window.location.href = 'room.php?roomname=' + encodeURIComponent(roomname);
            } else {
                // User needs to join first, show join form
                showForm('join');
                document.getElementById('join_room').value = roomname;
                document.getElementById('join_password').focus();
                queueNotification('Please enter the room password to join', 'info');
            }
        }

        // Get cookie value
        function getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        }

        // Start polling for real-time updates
        function startDataPolling() {
            dataPollingInterval = setInterval(() => {
                loadRealTimeData();
            }, POLLING_INTERVAL);
        }

        // Enhanced polling with different intervals for different data
        let fastPollingInterval = null;
        let slowPollingInterval = null;

        function startEnhancedPolling() {
            // Fast polling for critical data (online status, activity, friends, personal messages)
            fastPollingInterval = setInterval(() => {
                loadOnlineUsersCount();
                loadRecentActivity();
                loadFriendsData();
                sendPing();
                // Check for new personal messages if chatting with someone
                if (currentChatUser) {
                    loadMessages(currentChatUser.username);
                }
            }, 3000); // 3 seconds for faster personal messaging updates

            // Slow polling for less critical data (rooms, stats)
            slowPollingInterval = setInterval(() => {
                loadUserRooms();
                loadPlatformStats();
                // Add activity indicators after updates
                setTimeout(addActivityIndicators, 500);
            }, POLLING_INTERVAL); // 10 seconds
        }

        function stopEnhancedPolling() {
            if (fastPollingInterval) {
                clearInterval(fastPollingInterval);
                fastPollingInterval = null;
            }
            if (slowPollingInterval) {
                clearInterval(slowPollingInterval);
                slowPollingInterval = null;
            }
        }

        // Stop polling
        function stopDataPolling() {
            if (dataPollingInterval) {
                clearInterval(dataPollingInterval);
                dataPollingInterval = null;
            }
        }

        // Load friend-related data
        async function loadFriendsData() {
            try {
                await Promise.all([
                    loadFriendRequests(),
                    loadFriendsList()
                ]);
            } catch (error) {
                console.error('Error loading friends data:', error);
            }
        }

        // Search for friends by email
        async function searchFriends() {
            const emailInput = document.getElementById('friend-search');
            const email = emailInput.value.trim();

            if (!email) {
                queueNotification('Please enter an email address', 'warning');
                return;
            }

            try {
                const response = await fetch(`index.php?action=search_friends&email=${encodeURIComponent(email)}`);
                const data = await response.json();

                if (data.success) {
                    displayFriendSearchResults(data.users);
                } else {
                    queueNotification(data.error || 'Search failed', 'error');
                }
            } catch (error) {
                console.error('Friend search error:', error);
                queueNotification('Search failed', 'error');
            }
        }

        // Send friend request
async function sendFriendRequest(username) {
    try {
        const formData = new FormData();
        formData.append('friend_username', username);

        const response = await fetch('index.php?action=send_friend_request', {
            method: 'POST',
            body: formData
        });

        // Check if response is OK
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text();
        
        // Check if response is empty
        if (!text) {
            throw new Error('Empty response from server');
        }

        let data;
        try {
            data = JSON.parse(text);
        } catch (parseError) {
            console.error('JSON parse error:', parseError, 'Response text:', text);
            throw new Error('Invalid response from server');
        }

        if (data.success) {
            queueNotification('Friend request sent!', 'success');
            document.getElementById('friend-search-results').innerHTML = '';
            document.getElementById('friend-search').value = '';
        } else {
            queueNotification(data.error || 'Failed to send request', 'error');
        }
    } catch (error) {
        console.error('Send friend request error:', error);
        queueNotification('Failed to send friend request: ' + error.message, 'error');
    }
}

        // Load friend requests
        async function loadFriendRequests() {
            try {
                const response = await fetch('index.php?action=get_friend_requests');
                const data = await response.json();

                if (data.success) {
                    displayFriendRequests(data.requests);
                }
            } catch (error) {
                console.error('Error loading friend requests:', error);
            }
        }

        // Load friends list
        async function loadFriendsList() {
            try {
                const response = await fetch('index.php?action=get_friends');
                const data = await response.json();

                if (data.success) {
                    displayFriendsList(data.friends);
                }
            } catch (error) {
                console.error('Error loading friends list:', error);
            }
        }

        // Respond to friend request
        async function respondToFriendRequest(requestId, action) {
            try {
                const formData = new FormData();
                formData.append('request_id', requestId);
                formData.append('action', action);

                const response = await fetch('index.php?action=respond_friend_request', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    queueNotification(data.message, 'success');
                    loadFriendRequests();
                    loadFriendsList();
                } else {
                    queueNotification(data.error || 'Action failed', 'error');
                }
            } catch (error) {
                console.error('Respond to friend request error:', error);
                queueNotification('Action failed', 'error');
            }
        }

        // Display friend search results
        function displayFriendSearchResults(users) {
            const container = document.getElementById('friend-search-results');

            if (users.length === 0) {
                container.innerHTML = '<div class="text-muted text-center p-2">No users found with this email</div>';
                return;
            }

            let html = '';
            users.forEach(user => {
                html += `
                    <div class="user-item">
                        <div class="user-avatar">
                            ${user.username.charAt(0).toUpperCase()}
                        </div>
                        <div class="user-info">
                            <div class="user-name">${user.username}</div>
                            <div class="user-status">${user.email}</div>
                        </div>
                        <button onclick="sendFriendRequest('${user.username}')" class="btn btn-primary btn-sm">
                            Add Friend
                        </button>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // Display friend requests
        function displayFriendRequests(requests) {
            const container = document.getElementById('friend-requests-list');

            if (requests.length === 0) {
                container.innerHTML = '<div class="text-muted text-center p-2">No pending requests</div>';
                return;
            }

            let html = '';
            requests.forEach(request => {
                html += `
                    <div class="user-item">
                        <div class="user-avatar">
                            ${request.sender_username.charAt(0).toUpperCase()}
                        </div>
                        <div class="user-info">
                            <div class="user-name">${request.sender_username}</div>
                            <div class="user-status">${request.email}</div>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <button onclick="respondToFriendRequest(${request.id}, 'accept')" class="btn btn-success btn-sm">
                                Accept
                            </button>
                            <button onclick="respondToFriendRequest(${request.id}, 'decline')" class="btn btn-danger btn-sm">
                                Decline
                            </button>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // Display friends list
        function displayFriendsList(friends) {
            const container = document.getElementById('friends-list');

            if (friends.length === 0) {
                container.innerHTML = '<div class="text-muted text-center p-2">No friends yet</div>';
                return;
            }

            let html = '';
            friends.forEach(friend => {
                const isOnline = friend.is_online;
                const statusClass = isOnline ? '' : 'offline';
                const statusText = isOnline ? 'Online' : formatTimeAgo(friend.last_seen);

                html += `
                    <div class="user-item ${statusClass}" data-username="${friend.username}" onclick="selectUser({username: '${friend.username}', name: '${friend.username}', online: ${isOnline}})">
                        <div class="user-avatar">
                            ${friend.username.charAt(0).toUpperCase()}
                            <div class="online-status"></div>
                        </div>
                        <div class="user-info">
                            <div class="user-name">${friend.username}</div>
                            <div class="user-status">${statusText}</div>
                        </div>
                    </div>
                `;
            });

            container.innerHTML = html;
        }

        // Create user element for the sidebar
        function createUserElement(user) {
            const userItem = document.createElement('div');
            userItem.className = `user-item ${user.online ? '' : 'offline'}`;
            userItem.setAttribute('data-username', user.username);
            
            userItem.innerHTML = `
                <div class="user-avatar">
                    ${user.avatar}
                    <div class="online-status"></div>
                </div>
                <div class="user-info">
                    <div class="user-name">${user.name}</div>
                    <div class="user-status">${user.online ? 'Online' : 'Last seen 2 hours ago'}</div>
                </div>
            `;
            
            userItem.addEventListener('click', () => selectUser(user));
            
            return userItem;
        }

        // Select a user to chat with (personal messaging)
        function selectUser(user) {
            currentChatUser = user;

            // Update UI
            document.getElementById('chat-with-user').textContent = user.username;
            document.getElementById('message-input').disabled = false;
            document.getElementById('send-button').disabled = false;
            document.getElementById('message-input').placeholder = `Message ${user.username}...`;

            // Remove active class from all users
            document.querySelectorAll('.user-item').forEach(item => {
                item.classList.remove('active');
            });

            // Add active class to selected user
            document.querySelectorAll(`[data-username="${user.username}"]`).forEach(item => {
                item.classList.add('active');
            });

            // Load messages for this user
            loadMessages(user.username);

            // On mobile, close sidebar after selecting a user
            if (window.innerWidth <= 576) {
                toggleSidebar();
            }
        }

        // Load messages for a specific user (personal messaging)
        async function loadMessages(username) {
            try {
                const response = await fetch(`index.php?action=get_personal_messages&with_user=${encodeURIComponent(username)}`);
                const data = await response.json();

                if (data.success) {
                    displayPersonalMessages(data.messages, username);
                } else {
                    console.error('Failed to load messages:', data.error);
                }
            } catch (error) {
                console.error('Error loading messages:', error);
            }
        }

        // Create message element
        function createMessageElement(message) {
            const messageDiv = document.createElement('div');
            const isOutgoing = message.sender === 'current';

            messageDiv.className = `message ${isOutgoing ? 'message-outgoing' : 'message-incoming'}`;
            messageDiv.innerHTML = `
                <div class="message-content">${message.content}</div>
                <div class="message-time">${message.timestamp}</div>
            `;

            return messageDiv;
        }

        // Display personal messages
        function displayPersonalMessages(messages, withUser) {
            const container = document.getElementById('messages-container');

            if (messages.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-comments"></i>
                        <h3>No messages yet</h3>
                        <p>Start a conversation with ${withUser}</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = '';
            messages.forEach(message => {
                const messageElement = createPersonalMessageElement(message);
                container.appendChild(messageElement);
            });

            // Scroll to bottom
            container.scrollTop = container.scrollHeight;
        }

        // Create personal message element
        function createPersonalMessageElement(message) {
            const isOutgoing = message.from_user === '<?php echo $_SESSION['username']; ?>';
            const messageDiv = document.createElement('div');
            const timestamp = formatTimeAgo(message.created_at);

            messageDiv.className = `message ${isOutgoing ? 'message-outgoing' : 'message-incoming'}`;
            messageDiv.innerHTML = `
                <div class="message-content">${escapeHtml(message.message)}</div>
                <div class="message-time">${timestamp}</div>
            `;

            return messageDiv;
        }

        // Escape HTML to prevent XSS
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Setup event listeners
        function setupEventListeners() {
            // Message form submission
            document.getElementById('message-form').addEventListener('submit', function(e) {
                e.preventDefault();
                sendMessage();
            });

            // Auto-resize textarea
            document.getElementById('message-input').addEventListener('input', function() {
                this.style.height = 'auto';
                this.style.height = (this.scrollHeight) + 'px';
            });

            // Friend search input
            const friendSearchInput = document.getElementById('friend-search');
            if (friendSearchInput) {
                friendSearchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        searchFriends();
                    }
                });
            }
        }

        // Send a message (personal messaging)
        async function sendMessage() {
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();

            if (!message || !currentChatUser) return;

            // Disable input during send
            messageInput.disabled = true;
            document.getElementById('send-button').disabled = true;

            try {
                const formData = new FormData();
                formData.append('action', 'send_personal_message');
                formData.append('to_user', currentChatUser.username);
                formData.append('message', message);

                const response = await fetch('index.php', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    messageInput.value = '';
                    messageInput.style.height = 'auto';
                    loadMessages(currentChatUser.username); // Reload messages
                } else {
                    queueNotification('Failed to send message: ' + (data.error || 'Unknown error'), 'error');
                }
            } catch (error) {
                console.error('Error sending message:', error);
                queueNotification('Error sending message. Please try again.', 'error');
            } finally {
                messageInput.disabled = false;
                document.getElementById('send-button').disabled = messageInput.value.trim() === '';
                messageInput.focus();
            }
        }

        // Simulate a reply from the other user (removed - no longer needed)

        // Toggle sidebar visibility (mobile)
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('show');
        }

        // Toggle rooms area visibility
        function toggleRooms() {
            document.getElementById('rooms-area').classList.toggle('show');
        }

        // Toggle between create and join room forms
        function showForm(formType) {
            document.getElementById('createForm').classList.toggle('active', formType === 'create');
            document.getElementById('joinForm').classList.toggle('active', formType === 'join');

            // Update toggle buttons
            document.querySelectorAll('.toggle-buttons button').forEach(button => {
                button.classList.toggle('active',
                    (formType === 'create' && button.textContent === 'Create Room') ||
                    (formType === 'join' && button.textContent === 'Join Room')
                );
            });

            // Clear any previous form data
            if (formType === 'create') {
                document.getElementById('createForm').reset();
            } else if (formType === 'join') {
                document.getElementById('joinForm').reset();
            }
        }

        // Toggle dark/light theme with persistence
        // Toggle dark/light theme with persistence
async function toggleTheme() {
    try {
        const response = await fetch('index.php?action=toggle_theme', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'toggle_theme=true' // Simple payload
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const text = await response.text();
        console.log('Theme toggle response:', text); // Debug log

        if (!text) {
            throw new Error('Empty response from server');
        }

        const data = JSON.parse(text);

        if (data.success) {
            darkMode = data.dark_mode;
            const theme = data.theme;

            // Update the HTML data-theme attribute
            document.documentElement.setAttribute('data-theme', theme);

            // Update the button icon
            const themeIcon = document.querySelector('.fa-moon, .fa-sun');
            if (themeIcon) {
                themeIcon.className = darkMode ? 'fas fa-sun' : 'fas fa-moon';
            }

            // Show success notification
            queueNotification(`Switched to ${theme} theme` + (data.note ? ` (${data.note})` : ''), 'success');
        } else {
            // Fallback to local toggle
            console.warn('Theme toggle failed, using fallback:', data.error);
            fallbackThemeToggle();
        }
    } catch (error) {
        console.error('Theme toggle failed:', error);
        // Fallback to local toggle
        fallbackThemeToggle();
    }
}

        // Fallback theme toggle without API call
        function fallbackThemeToggle() {
            darkMode = !darkMode;
            const theme = darkMode ? 'dark' : 'light';

            // Update the HTML data-theme attribute
            document.documentElement.setAttribute('data-theme', theme);

            // Update the button icon
            const themeIcon = document.querySelector('.fa-moon, .fa-sun');
            if (themeIcon) {
                themeIcon.className = darkMode ? 'fas fa-sun' : 'fas fa-moon';
            }

            queueNotification(`Switched to ${theme} theme (local)`, 'info');
        }

        // Load user's theme preference on page load
        async function loadUserTheme() {
            try {
                const response = await fetch('index.php?action=get_user_theme');
                const data = await response.json();

                if (data.success && data.theme) {
                    darkMode = data.theme === 'dark';
                    document.documentElement.setAttribute('data-theme', data.theme);

                    // Update icon
                    const themeIcon = document.querySelector('.fa-moon, .fa-sun');
                    if (themeIcon) {
                        themeIcon.className = darkMode ? 'fas fa-sun' : 'fas fa-moon';
                    }
                }
            } catch (error) {
                console.error('Failed to load theme preference:', error);
            }
        }

        // Handle window resize
        window.addEventListener('resize', function() {
            if (window.innerWidth > 576) {
                document.getElementById('sidebar').classList.remove('show');
            }
            if (window.innerWidth > 768) {
                document.getElementById('rooms-area').classList.remove('show');
            }
        });

        // Auto-focus on room name input when create form is shown
        document.addEventListener('click', function(e) {
            if (e.target.closest('.toggle-buttons button')) {
                const formType = e.target.textContent === 'Create Room' ? 'create' : 'join';
                setTimeout(() => {
                    const inputId = formType === 'create' ? 'room' : 'join_room';
                    document.getElementById(inputId).focus();
                }, 100);
            }
        });

        // Handle page visibility change for polling
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                stopEnhancedPolling();
            } else {
                startEnhancedPolling();
                loadRealTimeData(); // Refresh data when page becomes visible
            }
        });

        // Close scan modal when clicking outside
        document.getElementById('scan-modal').addEventListener('click', function(event) {
            if (event.target === this) {
                closeScanModal();
            }
        });

        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            stopEnhancedPolling();
        });

        // Add live activity indicators
        function addActivityIndicators() {
            // Add pulsing effect to online count
            const onlineDisplay = document.getElementById('online-count-display');
            if (onlineDisplay && !onlineDisplay.style.animation) {
                onlineDisplay.style.animation = 'pulse 3s infinite';
            }

            // Add live notification for new activities
            const activityContainer = document.getElementById('recent-activity');
            if (activityContainer && activityContainer.children.length > 1) { // More than "No recent activity"
                const notificationBadge = document.querySelector('.notification-badge');
                if (notificationBadge && notificationBadge.classList.contains('hidden')) {
                    // This could be extended to show activity notifications
                    console.log('New activity detected');
                }
            }
        }

        // Add CSS animations for live indicators
        const style = document.createElement('style');
        style.textContent = `
            @keyframes blink {
                0%, 50% { opacity: 1; }
                51%, 100% { opacity: 0.3; }
            }

            .activity-indicator {
                animation: blink 2s infinite;
            }

            .live-update {
                transition: all 0.3s ease;
            }

            .live-update.updated {
                background: rgba(0, 123, 255, 0.1);
                transform: scale(1.02);
            }
        `;
        document.head.appendChild(style);

        // Mark elements as updated for visual feedback
        function markAsUpdated(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
                element.classList.add('live-update', 'updated');
                setTimeout(() => {
                    element.classList.remove('updated');
                }, 1000);
            }
        }

        // Live notification system
        let notificationQueue = [];
        let notificationInterval = null;

        function showLiveNotification(message, type = 'info', duration = 3000) {
            const container = document.getElementById('notification-container');
            if (!container) return;

            const notification = document.createElement('div');
            notification.className = `notification ${type} live-notification`;
            notification.style.cssText = `
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                padding: 1rem;
                margin-bottom: 0.5rem;
                box-shadow: var(--shadow-lg);
                transform: translateX(100%);
                transition: transform 0.3s ease;
                display: flex;
                align-items: flex-start;
                gap: 0.75rem;
                max-width: 100%;
                word-wrap: break-word;
            `;

            notification.innerHTML = `
                <div class="icon" style="flex-shrink: 0; margin-top: 0.125rem;">
                    ${getNotificationIcon(type)}
                </div>
                <div class="content" style="flex: 1; line-height: 1.4;">${message}</div>
                <button class="close" onclick="this.parentElement.remove()" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.25rem; flex-shrink: 0;">
                    <i class="fas fa-times"></i>
                </button>
            `;

            container.appendChild(notification);

            // Add entrance animation
            setTimeout(() => notification.style.transform = 'translateX(0)', 10);

            // Auto remove
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.style.transform = 'translateX(100%)';
                    setTimeout(() => notification.remove(), 300);
                }
            }, duration);
        }

        // Queue notifications to prevent spam
        function queueNotification(message, type = 'info') {
            notificationQueue.push({ message, type });

            if (!notificationInterval) {
                notificationInterval = setInterval(processNotificationQueue, 1000);
            }
        }

        function processNotificationQueue() {
            if (notificationQueue.length > 0) {
                const notification = notificationQueue.shift();
                showLiveNotification(notification.message, notification.type);

                if (notificationQueue.length === 0) {
                    clearInterval(notificationInterval);
                    notificationInterval = null;
                }
            }
        }

        // Get notification icon based on type
        function getNotificationIcon(type) {
            switch (type) {
                case 'success':
                    return '<i class="fas fa-check-circle" style="color: var(--accent-success);"></i>';
                case 'error':
                    return '<i class="fas fa-exclamation-circle" style="color: var(--accent-danger);"></i>';
                case 'warning':
                    return '<i class="fas fa-exclamation-triangle" style="color: var(--accent-warning);"></i>';
                case 'info':
                default:
                    return '<i class="fas fa-info-circle" style="color: var(--accent-info);"></i>';
            }
        }

        // Logout function
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                window.location.href = 'logout.php';
            }
        }

        // QR Code scanning functions
        function openScanModal() {
            document.getElementById('scan-modal').style.display = 'flex';
            document.getElementById('qr-file').value = '';
            document.getElementById('scan-result').style.display = 'none';
            document.getElementById('scan-preview').style.display = 'none';
            document.getElementById('process-btn').disabled = true;
        }

        function closeScanModal() {
            document.getElementById('scan-modal').style.display = 'none';
        }

        function handleFileSelect(event) {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    document.getElementById('preview-image').src = e.target.result;
                    document.getElementById('scan-preview').style.display = 'block';
                    document.getElementById('process-btn').disabled = false;
                };
                reader.readAsDataURL(file);
            }
        }

        function processQRCode() {
            const fileInput = document.getElementById('qr-file');
            const file = fileInput.files[0];

            if (!file) {
                alert('Please select a QR code image');
                return;
            }

            const resultDiv = document.getElementById('scan-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-spinner fa-spin"></i> Processing QR code...
                </div>
            `;

            document.getElementById('process-btn').disabled = true;

            // For now, show a message that QR decoding is not implemented
            // In a real implementation, you'd use a QR decoding service
            setTimeout(() => {
                resultDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <i class="fas fa-exclamation-triangle"></i> QR code decoding requires additional setup.
                        Please use room links for now or contact the administrator.
                    </div>
                `;
                document.getElementById('process-btn').disabled = false;
            }, 2000);
        }

        // Enhanced error handling with live notifications
        window.addEventListener('unhandledrejection', function(event) {
            console.error('Unhandled promise rejection:', event.reason);
            queueNotification('Connection error occurred. Some features may not work properly.', 'warning');
        });

        window.addEventListener('error', function(event) {
            console.error('JavaScript error:', event.error);
            queueNotification('An error occurred. Please refresh the page if issues persist.', 'error');
        });

        // Add notification styles
        const notificationStyles = document.createElement('style');
        notificationStyles.textContent = `
            .notification.success {
                border-left: 4px solid var(--accent-success);
            }

            .notification.error {
                border-left: 4px solid var(--accent-danger);
            }

            .notification.warning {
                border-left: 4px solid var(--accent-warning);
            }

            .notification.info {
                border-left: 4px solid var(--accent-info);
            }

            .live-notification .close:hover {
                color: var(--text-primary) !important;
            }
        `;
        document.head.appendChild(notificationStyles);


    // Initialize personal chat when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a page that has personal chat functionality
    const hasChatElements = document.getElementById('message-input') && 
                           document.getElementById('message-form') &&
                           document.getElementById('messages-container');
    
    if (hasChatElements) {
        personalChat.init();
    }
    
    // Update the selectUser function to use personalChat
    window.selectUser = function(user) {
        if (personalChat && typeof personalChat.selectUser === 'function') {
            personalChat.selectUser(user);
        }
    };
});
    </script>
</body>
</html>