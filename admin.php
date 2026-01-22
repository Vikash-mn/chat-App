<?php
session_start();
include("db_setup.php");

// Enhanced security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com;");

// Initialize variables
$active_tab = $_GET['tab'] ?? 'dashboard';
$error = '';
$success = '';
$search_query = $_GET['search'] ?? '';
$filter_type = $_GET['filter'] ?? '';

// Get current admin role with enhanced error handling
$current_admin_role = 'admin';
if (isset($_SESSION['admin_username'])) {
    try {
        $stmt = mysqli_prepare($conn, "SELECT role, is_active FROM admin_users WHERE username = ?");
        mysqli_stmt_bind_param($stmt, "s", $_SESSION['admin_username']);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        if ($admin_data = mysqli_fetch_assoc($result)) {
            // Check if admin is still active
            if (!$admin_data['is_active']) {
                log_admin_action('login_attempt_inactive_account');
                unset($_SESSION['admin_logged_in'], $_SESSION['admin_username'], $_SESSION['login_time']);
                header("Location: admin.php");
                exit();
            }
            $current_admin_role = $admin_data['role'];
        }
        mysqli_stmt_close($stmt);
    } catch (Exception $e) {
        error_log("Admin role fetch error: " . $e->getMessage());
    }
}

// Enhanced CSRF Protection with rotation
if (!isset($_SESSION['admin_csrf_token']) || (isset($_SESSION['csrf_generated']) && (time() - $_SESSION['csrf_generated']) > 1800)) {
    $_SESSION['admin_csrf_token'] = bin2hex(random_bytes(32));
    $_SESSION['csrf_generated'] = time();
}

// Enhanced input sanitization
function sanitize_input($data) {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Enhanced audit logging with error handling
function log_admin_action($action, $details = '') {
    global $conn;
    $username = $_SESSION['admin_username'] ?? 'Unknown';
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    try {
        $query = "INSERT INTO admin_audit_log (admin_username, action, details, ip_address, user_agent) 
                  VALUES (?, ?, ?, ?, ?)";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "sssss", $username, $action, $details, $ip, $user_agent);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
        return true;
    } catch (Exception $e) {
        error_log("Audit log error: " . $e->getMessage());
        return false;
    }
}

// Ensure audit log table exists with enhanced structure
$check_table = mysqli_query($conn, "SHOW TABLES LIKE 'admin_audit_log'");
if (mysqli_num_rows($check_table) == 0) {
    $create_table = "CREATE TABLE admin_audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_username VARCHAR(100) NOT NULL,
        action VARCHAR(255) NOT NULL,
        details TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_admin_username (admin_username),
        INDEX idx_created_at (created_at),
        INDEX idx_action (action)
    )";
    mysqli_query($conn, $create_table);
}

// Handle logout
if (isset($_GET['logout'])) {
    log_admin_action('logout');
    unset($_SESSION['admin_logged_in'], $_SESSION['admin_username'], $_SESSION['login_time']);
    session_destroy();
    header("Location: admin.php");
    exit();
}

// Enhanced form processing with validation
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        $error = 'Security token validation failed';
        log_admin_action('csrf_validation_failed');
        http_response_code(403);
    } 
    // Admin login
    elseif (isset($_POST['admin_login'])) {
        $admin_username = sanitize_input($_POST['admin_username'] ?? '');
        $admin_password = $_POST['admin_password'] ?? '';

        // Rate limiting for login attempts
        $login_attempts_key = 'login_attempts_' . $admin_username;
        if (!isset($_SESSION[$login_attempts_key])) {
            $_SESSION[$login_attempts_key] = 0;
        }
        
        if ($_SESSION[$login_attempts_key] >= 5) {
            $error = 'Too many login attempts. Please try again later.';
            log_admin_action('login_rate_limit_exceeded', "Username: $admin_username");
        } else {
            // Check admin credentials from database
            $stmt = mysqli_prepare($conn, "SELECT id, password_hash, is_active, role FROM admin_users WHERE username = ?");
            mysqli_stmt_bind_param($stmt, "s", $admin_username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $admin_user = mysqli_fetch_assoc($result);
            mysqli_stmt_close($stmt);

            if ($admin_user && $admin_user['is_active'] && password_verify($admin_password, $admin_user['password_hash'])) {
                $_SESSION['admin_logged_in'] = true;
                $_SESSION['admin_username'] = $admin_username;
                $_SESSION['login_time'] = time();
                $_SESSION['admin_role'] = $admin_user['role'];
                
                // Reset login attempts on successful login
                unset($_SESSION[$login_attempts_key]);

                // Update last login timestamp
                $update_stmt = mysqli_prepare($conn, "UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
                mysqli_stmt_bind_param($update_stmt, "i", $admin_user['id']);
                mysqli_stmt_execute($update_stmt);
                mysqli_stmt_close($update_stmt);

                log_admin_action('login_success');
                header("Location: admin.php");
                exit();
            } else {
                $_SESSION[$login_attempts_key]++;
                $error = 'Invalid admin credentials';
                log_admin_action('login_failed', "Username: $admin_username, Attempts: " . $_SESSION[$login_attempts_key]);
            }
        }
    }
    // Delete room with enhanced transaction handling
    elseif (isset($_POST['delete_room']) && isset($_SESSION['admin_logged_in'])) {
        $roomname = sanitize_input($_POST['roomname']);
        
        mysqli_begin_transaction($conn);
        try {
            $queries = [
                "DELETE FROM messages WHERE roomname = ?",
                "DELETE FROM room_users WHERE roomname = ?",
                "DELETE FROM typing_indicators WHERE roomname = ?",
                "DELETE FROM files WHERE roomname = ?",
                "DELETE FROM rooms WHERE roomname = ?"
            ];
            
            foreach ($queries as $query) {
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "s", $roomname);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
            }
            
            mysqli_commit($conn);
            $success = "Room '$roomname' deleted successfully";
            log_admin_action('room_deleted', "Room: $roomname");
            
        } catch (Exception $e) {
            mysqli_rollback($conn);
            $error = "Failed to delete room: " . $e->getMessage();
            log_admin_action('room_delete_failed', "Room: $roomname, Error: " . $e->getMessage());
        }
    }
    // Delete user with enhanced validation
elseif (isset($_POST['delete_user']) && isset($_SESSION['admin_logged_in'])) {
    $username = sanitize_input($_POST['username']);
    
    // Prevent admin from deleting themselves
    if ($username === $_SESSION['admin_username']) {
        $error = "You cannot delete your own account";
        log_admin_action('self_deletion_attempt');
    } else {
        $check_stmt = mysqli_prepare($conn, "SELECT username FROM users WHERE username = ?");
        mysqli_stmt_bind_param($check_stmt, "s", $username);
        mysqli_stmt_execute($check_stmt);
        $result = mysqli_stmt_get_result($check_stmt);
        
        if (mysqli_num_rows($result) > 0) {
            mysqli_begin_transaction($conn);
            try {
                // Delete user data from related tables
                $delete_queries = [
                    "DELETE FROM messages WHERE username = ?",
                    "DELETE FROM room_users WHERE username = ?",
                    "DELETE FROM typing_indicators WHERE username = ?",
                    "DELETE FROM files WHERE username = ?",
                    "DELETE FROM friend_requests WHERE sender_username = ?",
                    "DELETE FROM friend_requests WHERE receiver_username = ?",
                    "DELETE FROM friends WHERE user1 = ?",
                    "DELETE FROM friends WHERE user2 = ?",
                    "DELETE FROM personal_messages WHERE from_user = ?",
                    "DELETE FROM personal_messages WHERE to_user = ?",
                    "DELETE FROM join_requests WHERE username = ?",
                    "DELETE FROM room_admins WHERE username = ?",
                    "DELETE FROM user_preferences WHERE username = ?",
                    "DELETE FROM users WHERE username = ?"
                ];
                
                foreach ($delete_queries as $query) {
                    $stmt = mysqli_prepare($conn, $query);
                    mysqli_stmt_bind_param($stmt, "s", $username);
                    mysqli_stmt_execute($stmt);
                    mysqli_stmt_close($stmt);
                }
                
                mysqli_commit($conn);
                $success = "User '$username' deleted successfully";
                log_admin_action('user_deleted', "Username: $username");
                
            } catch (Exception $e) {
                mysqli_rollback($conn);
                $error = "Failed to delete user: " . $e->getMessage();
                log_admin_action('user_delete_failed', "Username: $username, Error: " . $e->getMessage());
            }
        } else {
            $error = "User not found";
        }
        mysqli_stmt_close($check_stmt);
    }
}
    // Delete file with enhanced error handling
    elseif (isset($_POST['delete_file']) && isset($_SESSION['admin_logged_in'])) {
        $file_id = (int)$_POST['file_id'];

        $stmt = mysqli_prepare($conn, "SELECT filepath, filename FROM files WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $file_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $file = mysqli_fetch_assoc($result);
        mysqli_free_result($result);
        mysqli_stmt_close($stmt);

        if ($file) {
            try {
                if (file_exists($file['filepath'])) {
                    if (!unlink($file['filepath'])) {
                        throw new Exception("Could not delete physical file");
                    }
                }

                $delete_stmt = mysqli_prepare($conn, "DELETE FROM files WHERE id = ?");
                mysqli_stmt_bind_param($delete_stmt, "i", $file_id);
                
                if (mysqli_stmt_execute($delete_stmt)) {
                    $success = "File '{$file['filename']}' deleted successfully";
                    log_admin_action('file_deleted', "File: {$file['filename']}");
                } else {
                    throw new Exception("Database deletion failed");
                }
                mysqli_stmt_close($delete_stmt);
            } catch (Exception $e) {
                $error = "Failed to delete file: " . $e->getMessage();
                log_admin_action('file_delete_failed', "File: {$file['filename']}, Error: " . $e->getMessage());
            }
        } else {
            $error = 'File not found';
        }
    }
    // Create room with enhanced validation
    elseif (isset($_POST['create_room']) && isset($_SESSION['admin_logged_in'])) {
        $roomname = sanitize_input($_POST['new_room_name']);
        $password = $_POST['new_room_password'] ?? '';
        $description = sanitize_input($_POST['new_room_description'] ?? '');

        if (empty($roomname)) {
            $error = 'Room name is required';
        } elseif (strlen($roomname) < 2 || strlen($roomname) > 50) {
            $error = 'Room name must be between 2 and 50 characters';
        } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $roomname)) {
            $error = 'Room name can only contain letters, numbers, hyphens, and underscores';
        } else {
            $stmt = mysqli_prepare($conn, "SELECT id FROM rooms WHERE roomname = ?");
            mysqli_stmt_bind_param($stmt, "s", $roomname);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $room_exists = mysqli_num_rows($result) > 0;
            mysqli_free_result($result);
            mysqli_stmt_close($stmt);

            if ($room_exists) {
                $error = 'Room already exists';
            } else {
                $hashed_password = !empty($password) ? password_hash($password, PASSWORD_DEFAULT) : '';
                
                $stmt = mysqli_prepare($conn, "INSERT INTO rooms (roomname, creator, password, description) VALUES (?, 'Admin', ?, ?)");
                mysqli_stmt_bind_param($stmt, "sss", $roomname, $hashed_password, $description);
                
                if (mysqli_stmt_execute($stmt)) {
                    $success = "Room '$roomname' created successfully";
                    log_admin_action('room_created', "Room: $roomname");
                } else {
                    $error = 'Failed to create room: ' . mysqli_error($conn);
                }
                mysqli_stmt_close($stmt);
            }
        }
    }
    // Reset room with enhanced error handling
    elseif (isset($_POST['reset_room']) && isset($_SESSION['admin_logged_in'])) {
        $roomname = sanitize_input($_POST['roomname']);

        mysqli_begin_transaction($conn);
        try {
            $queries = [
                "DELETE FROM messages WHERE roomname = ?",
                "DELETE FROM files WHERE roomname = ?",
                "DELETE FROM typing_indicators WHERE roomname = ?"
            ];

            $success_count = 0;
            foreach ($queries as $query) {
                $stmt = mysqli_prepare($conn, $query);
                mysqli_stmt_bind_param($stmt, "s", $roomname);
                if (mysqli_stmt_execute($stmt)) {
                    $success_count++;
                }
                mysqli_stmt_close($stmt);
            }

            mysqli_commit($conn);
            
            if ($success_count == count($queries)) {
                $success = "Room '$roomname' reset successfully";
                log_admin_action('room_reset', "Room: $roomname");
            } else {
                $error = 'Room reset partially completed';
            }
            
        } catch (Exception $e) {
            mysqli_rollback($conn);
            $error = "Room reset failed: " . $e->getMessage();
            log_admin_action('room_reset_failed', "Room: $roomname, Error: " . $e->getMessage());
        }
    }
    // Join room as admin with enhanced validation
    elseif (isset($_POST['join_room_admin']) && isset($_SESSION['admin_logged_in'])) {
        $roomname = sanitize_input($_POST['roomname']);

        $query = "SELECT id FROM rooms WHERE roomname = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $roomname);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $room_exists = mysqli_num_rows($result) > 0;
        mysqli_free_result($result);
        mysqli_stmt_close($stmt);

        if ($room_exists) {
            $_SESSION['username'] = 'Admin';
            $user_token = bin2hex(random_bytes(16));
            $query = "INSERT INTO room_users (roomname, username, user_token) VALUES (?, 'Admin', ?)
                     ON DUPLICATE KEY UPDATE user_token = VALUES(user_token), last_seen = CURRENT_TIMESTAMP";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "ss", $roomname, $user_token);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            setcookie('user_token_' . $roomname, $user_token, time() + (86400 * 30), "/");
            log_admin_action('joined_room_as_admin', "Room: $roomname");
            header("Location: room.php?roomname=" . urlencode($roomname));
            exit();
        } else {
            $error = 'Room not found';
        }
    }
    // Delete all files with enhanced error handling
    elseif (isset($_POST['delete_all_files']) && isset($_SESSION['admin_logged_in'])) {
        mysqli_begin_transaction($conn);
        try {
            $result = mysqli_query($conn, "SELECT id, filepath FROM files");
            $deleted_count = 0;
            $errors = [];
            
            while ($file = mysqli_fetch_assoc($result)) {
                if (file_exists($file['filepath'])) {
                    if (!unlink($file['filepath'])) {
                        $errors[] = "Could not delete file: " . $file['filepath'];
                    }
                }
                $deleted_count++;
            }
            
            mysqli_query($conn, "DELETE FROM files");
            mysqli_commit($conn);
            
            if (empty($errors)) {
                $success = "All files ($deleted_count) deleted successfully";
                log_admin_action('all_files_deleted', "Count: $deleted_count");
            } else {
                $error = "Some files could not be deleted. " . implode(", ", $errors);
                log_admin_action('all_files_delete_partial', "Deleted: $deleted_count, Errors: " . count($errors));
            }
        } catch (Exception $e) {
            mysqli_rollback($conn);
            $error = "Failed to delete all files: " . $e->getMessage();
            log_admin_action('all_files_delete_failed', "Error: " . $e->getMessage());
        }
    }
    // Optimize tables with enhanced error handling
    elseif (isset($_POST['optimize_tables']) && isset($_SESSION['admin_logged_in'])) {
        $tables = ['users', 'rooms', 'messages', 'files', 'room_users', 'admin_audit_log', 'admin_users'];
        $optimized_count = 0;
        $errors = [];
        
        foreach ($tables as $table) {
            try {
                if (mysqli_query($conn, "OPTIMIZE TABLE $table")) {
                    $optimized_count++;
                } else {
                    $errors[] = "Failed to optimize table: $table";
                }
            } catch (Exception $e) {
                $errors[] = "Error optimizing table $table: " . $e->getMessage();
            }
        }
        
        if (empty($errors)) {
            $success = "Optimized $optimized_count database tables";
            log_admin_action('tables_optimized', "Count: $optimized_count");
        } else {
            $error = "Optimized $optimized_count tables, but encountered errors: " . implode(", ", $errors);
            log_admin_action('tables_optimized_partial', "Optimized: $optimized_count, Errors: " . count($errors));
        }
    }
    // Clear audit log with confirmation
    elseif (isset($_POST['clear_audit_log']) && isset($_SESSION['admin_logged_in'])) {
        // Get count before deletion for logging
        $count_result = mysqli_query($conn, "SELECT COUNT(*) as count FROM admin_audit_log");
        $count = mysqli_fetch_assoc($count_result)['count'];
        
        if (mysqli_query($conn, "DELETE FROM admin_audit_log")) {
            $success = "Audit log cleared successfully ($count records removed)";
            log_admin_action('audit_log_cleared', "Records: $count");
        } else {
            $error = "Failed to clear audit log";
            log_admin_action('audit_log_clear_failed');
        }
    }
    // Add new admin (master admin only) with enhanced validation
    elseif (isset($_POST['add_admin']) && isset($_SESSION['admin_logged_in']) && $current_admin_role === 'master') {
        $new_username = sanitize_input($_POST['new_admin_username']);
        $new_email = sanitize_input($_POST['new_admin_email']);
        $new_password = $_POST['new_admin_password'];
        $confirm_password = $_POST['confirm_admin_password'];
        $new_role = $_POST['new_admin_role'] ?? 'admin';

        // Enhanced validation
        if (empty($new_username) || empty($new_email) || empty($new_password)) {
            $error = 'All fields are required';
        } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email format';
        } elseif (strlen($new_password) < 8) {
            $error = 'Password must be at least 8 characters long';
        } elseif (!preg_match('/[A-Z]/', $new_password)) {
            $error = 'Password must contain at least one uppercase letter';
        } elseif (!preg_match('/[a-z]/', $new_password)) {
            $error = 'Password must contain at least one lowercase letter';
        } elseif (!preg_match('/[0-9]/', $new_password)) {
            $error = 'Password must contain at least one number';
        } elseif (!preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $new_password)) {
            $error = 'Password must contain at least one special character';
        } elseif ($new_password !== $confirm_password) {
            $error = 'Passwords do not match';
        } else {
            // Check if username already exists
            $stmt = mysqli_prepare($conn, "SELECT id FROM admin_users WHERE username = ?");
            mysqli_stmt_bind_param($stmt, "s", $new_username);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if (mysqli_num_rows($result) > 0) {
                $error = 'Username already exists';
            } else {
                // Create new admin
                $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = mysqli_prepare($conn, "INSERT INTO admin_users (username, password_hash, email, role) VALUES (?, ?, ?, ?)");
                mysqli_stmt_bind_param($stmt, "ssss", $new_username, $password_hash, $new_email, $new_role);

                if (mysqli_stmt_execute($stmt)) {
                    $success = "Admin user '$new_username' created successfully";
                    log_admin_action('admin_created', "Username: $new_username, Role: $new_role");
                } else {
                    $error = 'Failed to create admin user: ' . mysqli_error($conn);
                }
            }
            mysqli_stmt_close($stmt);
        }
    }
    // Toggle admin status (master admin only) with enhanced validation
    elseif (isset($_POST['toggle_admin_status']) && isset($_SESSION['admin_logged_in']) && $current_admin_role === 'master') {
        $admin_id = (int)$_POST['admin_id'];
        $action = $_POST['action']; // 'activate' or 'deactivate'

        // Get admin info
        $stmt = mysqli_prepare($conn, "SELECT username, role FROM admin_users WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $admin_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $admin_info = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);

        if ($admin_info) {
            // Prevent deactivating master admin or self
            if ($admin_info['role'] === 'master') {
                $error = 'Cannot deactivate master admin';
            } elseif ($admin_info['username'] === $_SESSION['admin_username']) {
                $error = 'Cannot deactivate your own account';
            } else {
                $new_status = ($action === 'activate') ? 1 : 0;
                $stmt = mysqli_prepare($conn, "UPDATE admin_users SET is_active = ? WHERE id = ?");
                mysqli_stmt_bind_param($stmt, "ii", $new_status, $admin_id);

                if (mysqli_stmt_execute($stmt)) {
                    $status_text = $action === 'activate' ? 'activated' : 'deactivated';
                    $success = "Admin user '{$admin_info['username']}' $status_text successfully";
                    log_admin_action('admin_status_changed', "Username: {$admin_info['username']}, Action: $status_text");
                } else {
                    $error = 'Failed to update admin status';
                }
                mysqli_stmt_close($stmt);
            }
        } else {
            $error = 'Admin user not found';
        }
    }
    // Delete admin (master admin only) with enhanced validation
    elseif (isset($_POST['delete_admin']) && isset($_SESSION['admin_logged_in']) && $current_admin_role === 'master') {
        $admin_id = (int)$_POST['admin_id'];

        // Get admin info
        $stmt = mysqli_prepare($conn, "SELECT username, role FROM admin_users WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $admin_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $admin_info = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);

        if ($admin_info) {
            // Prevent deleting master admin or self
            if ($admin_info['role'] === 'master') {
                $error = 'Cannot delete master admin';
            } elseif ($admin_info['username'] === $_SESSION['admin_username']) {
                $error = 'Cannot delete your own account';
            } else {
                $stmt = mysqli_prepare($conn, "DELETE FROM admin_users WHERE id = ?");
                mysqli_stmt_bind_param($stmt, "i", $admin_id);

                if (mysqli_stmt_execute($stmt)) {
                    $success = "Admin user '{$admin_info['username']}' deleted successfully";
                    log_admin_action('admin_deleted', "Username: {$admin_info['username']}");
                } else {
                    $error = 'Failed to delete admin user';
                }
                mysqli_stmt_close($stmt);
            }
        } else {
            $error = 'Admin user not found';
        }
    }
    // Export data functionality
    elseif (isset($_POST['export_data']) && isset($_SESSION['admin_logged_in'])) {
        $export_type = $_POST['export_type'] ?? 'users';
        
        // Set headers for download
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $export_type . '_export_' . date('Y-m-d') . '.csv"');
        
        // Create output stream
        $output = fopen('php://output', 'w');
        
        // Add BOM for UTF-8
        fputs($output, $bom = (chr(0xEF) . chr(0xBB) . chr(0xBF)));
        
        switch ($export_type) {
            case 'users':
                fputcsv($output, ['Username', 'Email', 'Created At', 'Last Seen', 'Is Online']);
                $query = "SELECT username, email, created_at, last_seen, is_online FROM users ORDER BY created_at DESC";
                break;
            case 'rooms':
                fputcsv($output, ['Room Name', 'Creator', 'Created At', 'User Count', 'Message Count']);
                $query = "SELECT r.roomname, r.creator, r.created_at, 
                         COUNT(DISTINCT ru.username) as user_count, 
                         COUNT(DISTINCT m.id) as message_count
                  FROM rooms r
                  LEFT JOIN room_users ru ON r.roomname = ru.roomname
                  LEFT JOIN messages m ON r.roomname = m.roomname
                  GROUP BY r.roomname, r.creator, r.created_at
                  ORDER BY r.created_at DESC";
                break;
            case 'messages':
                fputcsv($output, ['Username', 'Message', 'Room', 'Timestamp']);
                $query = "SELECT username, msg, roomname, created_at FROM messages ORDER BY created_at DESC";
                break;
            default:
                fputcsv($output, ['Error', 'Invalid export type']);
                fclose($output);
                exit();
        }
        
        $result = mysqli_query($conn, $query);
        while ($row = mysqli_fetch_assoc($result)) {
            fputcsv($output, $row);
        }
        
        fclose($output);
        log_admin_action('data_exported', "Type: $export_type");
        exit();
    }
}

// Enhanced session timeout (1 hour) with warning
if (isset($_SESSION['login_time'])) {
    $session_duration = time() - $_SESSION['login_time'];
    if ($session_duration > 3600) {
        log_admin_action('session_timeout');
        unset($_SESSION['admin_logged_in'], $_SESSION['admin_username'], $_SESSION['login_time']);
        header("Location: admin.php");
        exit();
    } elseif ($session_duration > 3300) { // 55 minutes - show warning
        $session_warning = "Your session will expire in " . (60 - ceil($session_duration / 60)) . " minutes";
    }
}

// Redirect to login if not authenticated
if (!isset($_SESSION['admin_logged_in'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Login - Galaxy Chat</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <link rel="stylesheet" href="admin.css">
        <style>
            :root {
                --primary: #6366f1;
                --primary-dark: #4f46e5;
                --primary-light: #8b5cf6;
                --danger: #ef4444;
                --success: #10b981;
                --warning: #f59e0b;
                --bg-dark: #0f172a;
                --bg-darker: #020617;
                --card-bg: rgba(30, 41, 59, 0.8);
                --text-light: #e2e8f0;
                --text-lighter: #f8fafc;
                --border-light: rgba(255, 255, 255, 0.1);
                --gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background: var(--bg-dark);
                background-image: 
                    radial-gradient(at 47% 33%, hsl(215.32, 98%, 61%) 0, transparent 59%), 
                    radial-gradient(at 82% 65%, hsl(218.36, 98%, 61%) 0, transparent 55%);
                color: var(--text-lighter);
                font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                line-height: 1.6;
            }
            
            .admin-login-container {
                background: var(--card-bg);
                padding: 3rem;
                border-radius: 20px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                backdrop-filter: blur(16px);
                width: 100%;
                max-width: 440px;
                text-align: center;
                border: 1px solid var(--border-light);
                position: relative;
                overflow: hidden;
            }
            
            .admin-login-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: var(--gradient);
            }
            
            h1 {
                background: var(--gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 1.5rem;
                font-weight: 700;
                font-size: 2.2rem;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
            }
            
            .error {
                background: rgba(239, 68, 68, 0.1);
                color: var(--danger);
                padding: 1rem;
                border-radius: 12px;
                margin-bottom: 1.5rem;
                border: 1px solid rgba(239, 68, 68, 0.2);
                display: flex;
                align-items: center;
                gap: 0.5rem;
                font-size: 0.9rem;
            }
            
            .form-group {
                margin-bottom: 1.5rem;
                text-align: left;
            }
            
            label {
                display: block;
                margin-bottom: 0.5rem;
                color: var(--text-light);
                font-size: 0.9rem;
                font-weight: 500;
            }
            
            input {
                width: 100%;
                padding: 1rem 1.2rem;
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid var(--border-light);
                border-radius: 12px;
                color: var(--text-lighter);
                font-size: 1rem;
                transition: all 0.3s ease;
            }
            
            input:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
                background: rgba(15, 23, 42, 0.8);
            }
            
            button {
                width: 100%;
                padding: 1rem 1.2rem;
                background: var(--gradient);
                border: none;
                border-radius: 12px;
                color: white;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            button::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.5s;
            }
            
            button:hover::before {
                left: 100%;
            }
            
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.4);
            }
            
            .security-notice {
                margin-top: 1.5rem;
                padding: 1rem;
                background: rgba(245, 158, 11, 0.1);
                border: 1px solid rgba(245, 158, 11, 0.2);
                border-radius: 12px;
                font-size: 0.8rem;
                color: var(--text-light);
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            
            @media (max-width: 480px) {
                .admin-login-container {
                    padding: 2rem;
                    margin: 1rem;
                }
                
                h1 {
                    font-size: 1.8rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="admin-login-container">
            <h1><i class="fas fa-shield-alt"></i> Admin Portal</h1>
            <?php if ($error): ?>
                <div class="error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                <div class="form-group">
                    <label for="admin_username">Username</label>
                    <input type="text" id="admin_username" name="admin_username" placeholder="Admin username" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label for="admin_password">Password</label>
                    <input type="password" id="admin_password" name="admin_password" placeholder="Admin password" required autocomplete="current-password">
                </div>
                <button type="submit" name="admin_login">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>
            <div class="security-notice">
                <i class="fas fa-exclamation-triangle"></i> Restricted access. All activities are logged and monitored.
            </div>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// Fetch data based on active tab with enhanced filtering
$data = [];
$pagination = [];
$stats = [];
$filters = [];

// Get system statistics with enhanced metrics
$stats_queries = [
    'total_users' => "SELECT COUNT(*) as count FROM users",
    'total_rooms' => "SELECT COUNT(*) as count FROM rooms",
    'total_messages' => "SELECT COUNT(*) as count FROM messages",
    'total_files' => "SELECT COUNT(*) as count FROM files",
    'active_users' => "SELECT COUNT(DISTINCT username) as count FROM room_users WHERE last_seen > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
    'online_users' => "SELECT COUNT(*) as count FROM users WHERE is_online = 1",
    'storage_used' => "SELECT COALESCE(SUM(filesize), 0) as total_size FROM files",
    'today_messages' => "SELECT COUNT(*) as count FROM messages WHERE DATE(created_at) = CURDATE()",
    'today_users' => "SELECT COUNT(DISTINCT username) as count FROM users WHERE DATE(created_at) = CURDATE()"
];

foreach ($stats_queries as $key => $sql) {
    $result = mysqli_query($conn, $sql);
    $stats[$key] = $result ? mysqli_fetch_assoc($result)['count'] : 0;
}

// Tab-specific data fetching with enhanced filtering
if ($active_tab == 'dashboard') {
    // Recent activity
    $recent_messages = mysqli_query($conn, 
        "SELECT username, msg, roomname, created_at FROM messages 
         ORDER BY created_at DESC LIMIT 10"
    );
    $data['recent_messages'] = [];
    while ($row = mysqli_fetch_assoc($recent_messages)) {
        $data['recent_messages'][] = $row;
    }
    
    // Recent users
    $recent_users = mysqli_query($conn,
        "SELECT username, email, created_at FROM users 
         ORDER BY created_at DESC LIMIT 5"
    );
    $data['recent_users'] = [];
    while ($row = mysqli_fetch_assoc($recent_users)) {
        $data['recent_users'][] = $row;
    }
    
    // System health metrics
    $data['system_health'] = [
        'database_size' => get_database_size($conn),
        'active_sessions' => get_active_sessions_count($conn),
        'server_uptime' => get_server_uptime(),
        'php_version' => PHP_VERSION
    ];

} elseif ($active_tab == 'users') {
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = 20;
    $offset = ($page - 1) * $limit;
    
    $where = "";
    $params = [];
    $types = "";
    
    if (!empty($search_query)) {
        $where = "WHERE (u.username LIKE ? OR u.email LIKE ?)";
        $params = ["%$search_query%", "%$search_query%"];
        $types = "ss";
    }
    
    if (!empty($filter_type)) {
        if ($where) {
            $where .= " AND ";
        } else {
            $where = "WHERE ";
        }
        
        switch ($filter_type) {
            case 'online':
                $where .= "u.is_online = 1";
                break;
            case 'offline':
                $where .= "u.is_online = 0";
                break;
            case 'recent':
                $where .= "u.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
            case 'active':
                $where .= "u.last_seen > DATE_SUB(NOW(), INTERVAL 1 DAY)";
                break;
        }
    }
    
    $count_query = "SELECT COUNT(*) as total FROM users u $where";
    $count_stmt = mysqli_prepare($conn, $count_query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($count_stmt, $types, ...$params);
    }
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $total_rows = mysqli_fetch_assoc($count_result)['total'];
    $total_pages = ceil($total_rows / $limit);
    mysqli_stmt_close($count_stmt);
    
    $query = "SELECT u.username, u.email, u.created_at, u.last_seen, u.is_online,
                     COUNT(DISTINCT ru.roomname) as room_count,
                     COUNT(DISTINCT m.id) as message_count
               FROM users u
               LEFT JOIN room_users ru ON u.username = ru.username
               LEFT JOIN messages m ON u.username = m.username
               $where
               GROUP BY u.username, u.email, u.created_at, u.last_seen, u.is_online
               ORDER BY u.created_at DESC
               LIMIT $limit OFFSET $offset";
              
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    mysqli_stmt_close($stmt);
    
    $pagination = ['page' => $page, 'total_pages' => $total_pages];
    $filters = [
        'all' => 'All Users',
        'online' => 'Online',
        'offline' => 'Offline',
        'recent' => 'Recent (7 days)',
        'active' => 'Active (24h)'
    ];

} elseif ($active_tab == 'rooms') {
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = 20;
    $offset = ($page - 1) * $limit;
    
    $where = "";
    $params = [];
    $types = "";
    
    if (!empty($search_query)) {
        $where = "WHERE (r.roomname LIKE ? OR r.creator LIKE ? OR r.description LIKE ?)";
        $params = ["%$search_query%", "%$search_query%", "%$search_query%"];
        $types = "sss";
    }
    
    if (!empty($filter_type)) {
        if ($where) {
            $where .= " AND ";
        } else {
            $where = "WHERE ";
        }
        
        switch ($filter_type) {
            case 'active':
                $where .= "ru.last_seen > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
                break;
            case 'popular':
                $where .= "1=1";
                // We'll sort by user_count later
                break;
            case 'recent':
                $where .= "r.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
        }
    }
    
    $count_query = "SELECT COUNT(DISTINCT r.roomname) as total FROM rooms r 
                   LEFT JOIN room_users ru ON r.roomname = ru.roomname $where";
    $count_stmt = mysqli_prepare($conn, $count_query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($count_stmt, $types, ...$params);
    }
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $total_rows = mysqli_fetch_assoc($count_result)['total'];
    $total_pages = ceil($total_rows / $limit);
    mysqli_stmt_close($count_stmt);
    
    $order_by = "r.created_at DESC";
    if ($filter_type == 'popular') {
        $order_by = "user_count DESC, r.created_at DESC";
    }
    
    $query = "SELECT r.roomname, r.creator, r.created_at, r.description,
                     COUNT(DISTINCT ru.username) as user_count, 
                     COUNT(DISTINCT m.id) as message_count
              FROM rooms r
              LEFT JOIN room_users ru ON r.roomname = ru.roomname
              LEFT JOIN messages m ON r.roomname = m.roomname
              $where
              GROUP BY r.roomname, r.creator, r.created_at, r.description
              ORDER BY $order_by
              LIMIT $limit OFFSET $offset";
              
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    mysqli_stmt_close($stmt);
    
    $pagination = ['page' => $page, 'total_pages' => $total_pages];
    $filters = [
        'all' => 'All Rooms',
        'active' => 'Active Now',
        'popular' => 'Most Popular',
        'recent' => 'Recently Created'
    ];

} elseif ($active_tab == 'messages') {
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = 50;
    $offset = ($page - 1) * $limit;
    
    $where = "";
    $params = [];
    $types = "";
    
    if (!empty($search_query)) {
        $where = "WHERE (m.msg LIKE ? OR m.username LIKE ? OR m.roomname LIKE ?)";
        $params = ["%$search_query%", "%$search_query%", "%$search_query%"];
        $types = "sss";
    }
    
    if (!empty($filter_type)) {
        if ($where) {
            $where .= " AND ";
        } else {
            $where = "WHERE ";
        }
        
        switch ($filter_type) {
            case 'today':
                $where .= "DATE(m.created_at) = CURDATE()";
                break;
            case 'week':
                $where .= "m.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
            case 'images':
                $where .= "m.msg LIKE '%<img%'";
                break;
            case 'links':
                $where .= "m.msg LIKE '%http%'";
                break;
        }
    }
    
    $count_query = "SELECT COUNT(*) as total FROM messages m $where";
    $count_stmt = mysqli_prepare($conn, $count_query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($count_stmt, $types, ...$params);
    }
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $total_rows = mysqli_fetch_assoc($count_result)['total'];
    $total_pages = ceil($total_rows / $limit);
    mysqli_stmt_close($count_stmt);
    
    $query = "SELECT m.id, m.username, m.msg, m.roomname, m.created_at
              FROM messages m
              $where
              ORDER BY m.created_at DESC 
              LIMIT $limit OFFSET $offset";
              
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    mysqli_stmt_close($stmt);
    
    $pagination = ['page' => $page, 'total_pages' => $total_pages];
    $filters = [
        'all' => 'All Messages',
        'today' => 'Today',
        'week' => 'This Week',
        'images' => 'With Images',
        'links' => 'With Links'
    ];

} elseif ($active_tab == 'files') {
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = 20;
    $offset = ($page - 1) * $limit;
    
    $where = "";
    $params = [];
    $types = "";
    
    if (!empty($search_query)) {
        $where = "WHERE (f.filename LIKE ? OR f.username LIKE ? OR f.roomname LIKE ?)";
        $params = ["%$search_query%", "%$search_query%", "%$search_query%"];
        $types = "sss";
    }
    
    if (!empty($filter_type)) {
        if ($where) {
            $where .= " AND ";
        } else {
            $where = "WHERE ";
        }
        
        switch ($filter_type) {
            case 'images':
                $where .= "f.filename REGEXP '\\.(jpg|jpeg|png|gif|webp)$'";
                break;
            case 'documents':
                $where .= "f.filename REGEXP '\\.(pdf|doc|docx|txt)$'";
                break;
            case 'large':
                $where .= "f.filesize > 10485760"; // 10MB
                break;
            case 'recent':
                $where .= "f.uploaded_at > DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
        }
    }
    
    $count_query = "SELECT COUNT(*) as total FROM files f $where";
    $count_stmt = mysqli_prepare($conn, $count_query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($count_stmt, $types, ...$params);
    }
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $total_rows = mysqli_fetch_assoc($count_result)['total'];
    $total_pages = ceil($total_rows / $limit);
    mysqli_stmt_close($count_stmt);
    
    $query = "SELECT f.id, f.filename, f.filepath, f.filesize, f.username, f.roomname, f.uploaded_at
              FROM files f
              $where
              ORDER BY f.uploaded_at DESC 
              LIMIT $limit OFFSET $offset";
              
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    mysqli_stmt_close($stmt);
    
    $pagination = ['page' => $page, 'total_pages' => $total_pages];
    $filters = [
        'all' => 'All Files',
        'images' => 'Images',
        'documents' => 'Documents',
        'large' => 'Large Files (>10MB)',
        'recent' => 'Recent (7 days)'
    ];

} elseif ($active_tab == 'audit-log') {
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = 50;
    $offset = ($page - 1) * $limit;
    
    $where = "";
    $params = [];
    $types = "";
    
    if (!empty($search_query)) {
        $where = "WHERE (admin_username LIKE ? OR action LIKE ? OR details LIKE ? OR ip_address LIKE ?)";
        $params = ["%$search_query%", "%$search_query%", "%$search_query%", "%$search_query%"];
        $types = "ssss";
    }
    
    if (!empty($filter_type)) {
        if ($where) {
            $where .= " AND ";
        } else {
            $where = "WHERE ";
        }
        
        switch ($filter_type) {
            case 'today':
                $where .= "DATE(created_at) = CURDATE()";
                break;
            case 'week':
                $where .= "created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
            case 'critical':
                $where .= "action IN ('login_failed', 'csrf_validation_failed', 'admin_created', 'admin_deleted')";
                break;
            case 'current_user':
                $where .= "admin_username = ?";
                $params[] = $_SESSION['admin_username'];
                $types .= "s";
                break;
        }
    }
    
    $count_query = "SELECT COUNT(*) as total FROM admin_audit_log $where";
    $count_stmt = mysqli_prepare($conn, $count_query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($count_stmt, $types, ...$params);
    }
    mysqli_stmt_execute($count_stmt);
    $count_result = mysqli_stmt_get_result($count_stmt);
    $total_rows = mysqli_fetch_assoc($count_result)['total'];
    $total_pages = ceil($total_rows / $limit);
    mysqli_stmt_close($count_stmt);
    
    $query = "SELECT admin_username, action, details, ip_address, user_agent, created_at 
              FROM admin_audit_log 
              $where
              ORDER BY created_at DESC 
              LIMIT $limit OFFSET $offset";
              
    $stmt = mysqli_prepare($conn, $query);
    if (!empty($params)) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    mysqli_stmt_close($stmt);
    
    $pagination = ['page' => $page, 'total_pages' => $total_pages];
    $filters = [
        'all' => 'All Logs',
        'today' => 'Today',
        'week' => 'This Week',
        'critical' => 'Critical Actions',
        'current_user' => 'My Actions'
    ];
}

// Helper functions for system health
function get_database_size($conn) {
    $result = mysqli_query($conn, "SELECT 
        ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size_mb 
        FROM information_schema.tables 
        WHERE table_schema = DATABASE()");
    if ($result && $row = mysqli_fetch_assoc($result)) {
        return $row['size_mb'] . ' MB';
    }
    return 'Unknown';
}

function get_active_sessions_count($conn) {
    $result = mysqli_query($conn, "SELECT COUNT(DISTINCT username) as count FROM room_users WHERE last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
    if ($result && $row = mysqli_fetch_assoc($result)) {
        return $row['count'];
    }
    return 0;
}

function get_server_uptime() {
    if (function_exists('shell_exec')) {
        $uptime = shell_exec('uptime -p');
        return $uptime ? trim($uptime) : 'Unknown';
    }
    return 'Unknown';
}

// Close database connection at the end
mysqli_close($conn);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Portal - Galaxy Chat</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --primary-light: #8b5cf6;
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
            --info: #06b6d4;
            --bg-dark: #0f172a;
            --bg-darker: #020617;
            --card-bg: rgba(30, 41, 59, 0.8);
            --text-light: #e2e8f0;
            --text-lighter: #f8fafc;
            --text-muted: #94a3b8;
            --border-light: rgba(255, 255, 255, 0.1);
            --border-medium: rgba(255, 255, 255, 0.2);
            --gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%);
            --shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            --radius: 12px;
            --radius-lg: 16px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: var(--bg-dark);
            background-image: 
                radial-gradient(at 47% 33%, hsl(215.32, 98%, 61%) 0, transparent 59%), 
                radial-gradient(at 82% 65%, hsl(218.36, 98%, 61%) 0, transparent 55%);
            color: var(--text-lighter);
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .admin-container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: var(--radius-lg);
            padding: 2rem;
            backdrop-filter: blur(16px);
            border: 1px solid var(--border-light);
            margin: 20px;
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
        }
        
        .admin-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient);
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-light);
        }
        
        .header h1 {
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
            font-size: 2.2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .header-info {
            display: flex;
            align-items: center;
            gap: 1rem;
            color: var(--text-light);
            font-size: 0.9rem;
            flex-wrap: wrap;
        }
        
        .header-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .search-filter-container {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        
        .search-box {
            flex: 1;
            min-width: 300px;
            display: flex;
            gap: 0.5rem;
        }
        
        .search-box input, .filter-select select {
            flex: 1;
            padding: 0.8rem 1rem;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-light);
            border-radius: var(--radius);
            color: var(--text-lighter);
            transition: var(--transition);
        }
        
        .search-box input:focus, .filter-select select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
            background: rgba(15, 23, 42, 0.8);
        }
        
        .filter-select {
            min-width: 200px;
        }
        
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            background: rgba(15, 23, 42, 0.5);
            padding: 0.5rem;
            border-radius: var(--radius);
        }
        
        .tab {
            padding: 0.8rem 1.5rem;
            background: transparent;
            border: 1px solid transparent;
            border-radius: var(--radius);
            color: var(--text-light);
            text-decoration: none;
            transition: var(--transition);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 500;
        }
        
        .tab.active, .tab:hover {
            background: rgba(99, 102, 241, 0.1);
            color: var(--text-lighter);
            border-color: var(--primary);
            transform: translateY(-2px);
        }
        
        .alert {
            padding: 1rem 1.5rem;
            border-radius: var(--radius);
            margin-bottom: 1.5rem;
            border: 1px solid;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: var(--transition);
        }
        
        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--success);
            border-color: rgba(16, 185, 129, 0.2);
        }
        
        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border-color: rgba(239, 68, 68, 0.2);
        }
        
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            color: var(--warning);
            border-color: rgba(245, 158, 11, 0.2);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: rgba(15, 23, 42, 0.5);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-light);
        }
        
        th {
            background: rgba(99, 102, 241, 0.1);
            color: var(--primary);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }
        
        .stat-card {
            background: rgba(15, 23, 42, 0.6);
            padding: 1.5rem;
            border-radius: var(--radius);
            text-align: center;
            border: 1px solid var(--border-light);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gradient);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-light);
            font-size: 0.9rem;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.7rem 1.2rem;
            border: none;
            border-radius: var(--radius);
            text-decoration: none;
            font-size: 0.9rem;
            cursor: pointer;
            transition: var(--transition);
            font-weight: 500;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: var(--gradient);
            color: white;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-warning {
            background: var(--warning);
            color: black;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-info {
            background: var(--info);
            color: white;
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-lighter);
            border: 1px solid var(--border-light);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        
        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.1);
            color: white;
            border: 1px solid var(--border-light);
            padding: 0.8rem 1.5rem;
            border-radius: var(--radius);
            text-decoration: none;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .logout-btn:hover {
            background: rgba(255,255,255,0.2);
            transform: translateY(-2px);
        }
        
        .file-link {
            color: var(--primary);
            text-decoration: none;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .file-link:hover {
            color: var(--primary-light);
            text-decoration: underline;
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            margin-top: 2rem;
            flex-wrap: wrap;
        }
        
        .pagination a, .pagination span {
            padding: 0.6rem 1rem;
            border: 1px solid var(--border-light);
            border-radius: var(--radius);
            text-decoration: none;
            color: var(--text-light);
            transition: var(--transition);
            font-size: 0.9rem;
        }
        
        .pagination a:hover, .pagination .current {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }
        
        .online-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            margin-right: 0.5rem;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .offline-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--danger);
            margin-right: 0.5rem;
        }
        
        .card {
            background: rgba(15, 23, 42, 0.6);
            padding: 1.5rem;
            border-radius: var(--radius);
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-light);
            box-shadow: var(--shadow);
        }
        
        .card h3 {
            color: var(--text-lighter);
            margin-bottom: 1rem;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-light);
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 0.8rem 1rem;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-light);
            border-radius: var(--radius);
            color: var(--text-lighter);
            transition: var(--transition);
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
            background: rgba(15, 23, 42, 0.8);
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        
        .grid-3 {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 1.5rem;
        }
        
        .action-buttons {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .recent-activity {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .activity-item {
            padding: 1rem;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: var(--transition);
        }
        
        .activity-item:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .activity-item:last-child {
            border-bottom: none;
        }
        
        .activity-content {
            flex: 1;
        }
        
        .activity-time {
            color: var(--text-muted);
            font-size: 0.8rem;
            white-space: nowrap;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .badge-success {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .badge-danger {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
        }
        
        .badge-warning {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }
        
        .badge-info {
            background: rgba(6, 182, 212, 0.2);
            color: var(--info);
        }
        
        .badge-primary {
            background: rgba(99, 102, 241, 0.2);
            color: var(--primary);
        }

        
        .system-health {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .health-item {
            background: rgba(15, 23, 42, 0.6);
            padding: 1rem;
            border-radius: var(--radius);
            text-align: center;
            border: 1px solid var(--border-light);
        }
        
        .health-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--text-lighter);
            margin-bottom: 0.5rem;
        }
        
        .health-label {
            color: var(--text-light);
            font-size: 0.8rem;
        }
        
        .export-options {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }
        
        /* Responsive Design */
        @media (max-width: 1024px) {
            .grid-2, .grid-3 {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .admin-container {
                margin: 10px;
                padding: 1.5rem;
            }
            
            .header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .header-actions {
                justify-content: center;
            }
            
            .tabs {
                justify-content: center;
            }
            
            .tab {
                padding: 0.6rem 1rem;
                font-size: 0.8rem;
            }
            
            table {
                font-size: 0.8rem;
            }
            
            th, td {
                padding: 0.6rem 0.4rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .search-filter-container {
                flex-direction: column;
            }
            
            .search-box {
                min-width: 100%;
            }
            
            .action-buttons {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                justify-content: center;
            }
        }
        
        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.5rem;
            }
            
            .tab {
                padding: 0.5rem 0.8rem;
                font-size: 0.75rem;
            }
            
            .header-info {
                flex-direction: column;
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <div class="header">
            <div>
                <h1><i class="fas fa-shield-alt"></i> Galaxy Chat Admin</h1>
                <div class="header-info">
                    <span>Welcome, <?php echo htmlspecialchars($_SESSION['admin_username']); ?></span>
                    <span>•</span>
                    <span>Role: <span class="badge badge-primary"><?php echo htmlspecialchars($current_admin_role); ?></span></span>
                    <span>•</span>
                    <span>Session: <?php echo round((time() - $_SESSION['login_time']) / 60); ?> min</span>
                    <span>•</span>
                    <span><?php echo date('M j, Y g:i A'); ?></span>
                </div>
            </div>
            <div class="header-actions">
                <a href="index.php" class="btn btn-primary"><i class="fas fa-arrow-left"></i> Back to Chat</a>
                <a href="admin.php?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </div>

        <?php if (isset($session_warning)): ?>
            <div class="alert alert-warning">
                <i class="fas fa-clock"></i> <?php echo $session_warning; ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <!-- Search and Filter Container -->
        <?php if (in_array($active_tab, ['users', 'rooms', 'messages', 'files', 'audit-log'])): ?>
        <div class="search-filter-container">
            <div class="search-box">
                <form method="GET" style="display: flex; width: 100%; gap: 0.5rem;">
                    <input type="hidden" name="tab" value="<?php echo $active_tab; ?>">
                    <input type="text" name="search" placeholder="Search..." value="<?php echo htmlspecialchars($search_query); ?>">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Search</button>
                    <?php if (!empty($search_query) || !empty($filter_type)): ?>
                        <a href="admin.php?tab=<?php echo $active_tab; ?>" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </form>
            </div>
            
            <?php if (!empty($filters)): ?>
            <div class="filter-select">
                <form method="GET" id="filter-form">
                    <input type="hidden" name="tab" value="<?php echo $active_tab; ?>">
                    <?php if (!empty($search_query)): ?>
                        <input type="hidden" name="search" value="<?php echo htmlspecialchars($search_query); ?>">
                    <?php endif; ?>
                    <select name="filter" onchange="document.getElementById('filter-form').submit()">
                        <?php foreach ($filters as $value => $label): ?>
                            <option value="<?php echo $value; ?>" <?php echo $filter_type == $value ? 'selected' : ''; ?>>
                                <?php echo $label; ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <div class="tabs">
            <a href="admin.php?tab=dashboard" class="tab <?php echo $active_tab == 'dashboard' ? 'active' : ''; ?>">
                <i class="fas fa-tachometer-alt"></i> Dashboard
            </a>
            <a href="admin.php?tab=users" class="tab <?php echo $active_tab == 'users' ? 'active' : ''; ?>">
                <i class="fas fa-users"></i> Users
            </a>
            <a href="admin.php?tab=rooms" class="tab <?php echo $active_tab == 'rooms' ? 'active' : ''; ?>">
                <i class="fas fa-door-open"></i> Rooms
            </a>
            <a href="admin.php?tab=messages" class="tab <?php echo $active_tab == 'messages' ? 'active' : ''; ?>">
                <i class="fas fa-comments"></i> Messages
            </a>
            <a href="admin.php?tab=files" class="tab <?php echo $active_tab == 'files' ? 'active' : ''; ?>">
                <i class="fas fa-file"></i> Files
            </a>
            <?php if ($current_admin_role === 'master'): ?>
            <a href="admin.php?tab=admin-management" class="tab <?php echo $active_tab == 'admin-management' ? 'active' : ''; ?>">
                <i class="fas fa-user-shield"></i> Admin Management
            </a>
            <?php endif; ?>
            <a href="admin.php?tab=audit-log" class="tab <?php echo $active_tab == 'audit-log' ? 'active' : ''; ?>">
                <i class="fas fa-clipboard-list"></i> Audit Log
            </a>
        </div>

        <!-- Dashboard Tab -->
        <?php if ($active_tab == 'dashboard'): ?>
            <h2><i class="fas fa-tachometer-alt"></i> System Dashboard</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['total_users']; ?></div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['total_rooms']; ?></div>
                    <div class="stat-label">Active Rooms</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['total_messages']; ?></div>
                    <div class="stat-label">Messages Sent</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['total_files']; ?></div>
                    <div class="stat-label">Files Uploaded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['active_users']; ?></div>
                    <div class="stat-label">Active Users (1h)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['online_users']; ?></div>
                    <div class="stat-label">Online Now</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $stats['today_messages']; ?></div>
                    <div class="stat-label">Messages Today</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo number_format($stats['storage_used'] / (1024 * 1024), 2); ?> MB</div>
                    <div class="stat-label">Storage Used</div>
                </div>
            </div>

            <div class="card">
                <h3><i class="fas fa-heartbeat"></i> System Health</h3>
                <div class="system-health">
                    <div class="health-item">
                        <div class="health-value"><?php echo $data['system_health']['database_size']; ?></div>
                        <div class="health-label">Database Size</div>
                    </div>
                    <div class="health-item">
                        <div class="health-value"><?php echo $data['system_health']['active_sessions']; ?></div>
                        <div class="health-label">Active Sessions</div>
                    </div>
                    <div class="health-item">
                        <div class="health-value"><?php echo $data['system_health']['server_uptime']; ?></div>
                        <div class="health-label">Server Uptime</div>
                    </div>
                    <div class="health-item">
                        <div class="health-value"><?php echo $data['system_health']['php_version']; ?></div>
                        <div class="health-label">PHP Version</div>
                    </div>
                </div>
            </div>

            <div class="grid-2">
                <div class="card">
                    <h3><i class="fas fa-comment"></i> Recent Messages</h3>
                    <div class="recent-activity">
                        <?php foreach ($data['recent_messages'] as $message): ?>
                            <div class="activity-item">
                                <div class="activity-content">
                                    <strong><?php echo htmlspecialchars($message['username']); ?></strong>
                                    <span>in <?php echo htmlspecialchars($message['roomname']); ?>:</span>
                                    <br>
                                    <span><?php echo htmlspecialchars(substr($message['msg'], 0, 100)); ?></span>
                                </div>
                                <div class="activity-time">
                                    <?php echo date('H:i', strtotime($message['created_at'])); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <div class="card">
                    <h3><i class="fas fa-user-plus"></i> Recent Users</h3>
                    <div class="recent-activity">
                        <?php foreach ($data['recent_users'] as $user): ?>
                            <div class="activity-item">
                                <div class="activity-content">
                                    <strong><?php echo htmlspecialchars($user['username']); ?></strong>
                                    <br>
                                    <span><?php echo htmlspecialchars($user['email']); ?></span>
                                </div>
                                <div class="activity-time">
                                    <?php echo date('M j', strtotime($user['created_at'])); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

        <!-- Users Tab -->
        <?php elseif ($active_tab == 'users'): ?>
            <h2><i class="fas fa-users"></i> User Management</h2>
            <p>Total Users: <?php echo $stats['total_users']; ?> | Online: <?php echo $stats['online_users']; ?> | New Today: <?php echo $stats['today_users']; ?></p>
            
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Status</th>
                        <th>Joined</th>
                        <th>Last Seen</th>
                        <th>Rooms</th>
                        <th>Messages</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
        <?php foreach ($data as $user): ?>
            <tr>
                <td><?php echo htmlspecialchars($user['username']); ?></td>
                <td><?php echo htmlspecialchars($user['email']); ?></td>
                <td>
                    <?php if ($user['is_online']): ?>
                        <span class="online-indicator"></span> Online
                    <?php else: ?>
                        <span class="offline-indicator"></span> Offline
                    <?php endif; ?>
                </td>
                <td><?php echo date('M j, Y', strtotime($user['created_at'])); ?></td>
                <td><?php echo $user['last_seen'] ? date('M j, Y H:i', strtotime($user['last_seen'])) : 'Never'; ?></td>
                <td>
                    <form method="POST" onsubmit="return confirm('Are you sure you want to delete user: <?php echo htmlspecialchars($user['username']); ?>?')" style="display: inline;">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                        <button type="submit" name="delete_user" class="btn btn-danger btn-sm">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
            
            <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                        <a href="admin.php?tab=users&page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) : ''; ?><?php echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : ''; ?>" 
                           class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>

        <!-- Rooms Tab -->
        <?php elseif ($active_tab == 'rooms'): ?>
            <h2><i class="fas fa-door-open"></i> Room Management</h2>
            <p>Total Rooms: <?php echo $stats['total_rooms']; ?></p>
            
            <div class="action-buttons" style="margin-bottom: 1rem;">
                <button type="button" class="btn btn-success" onclick="document.getElementById('create-room-form').style.display='block'">
                    <i class="fas fa-plus"></i> Create New Room
                </button>
            </div>
            
            <div id="create-room-form" class="card" style="display: none; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-plus-circle"></i> Create New Room</h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <div class="form-group">
                        <label for="new_room_name">Room Name *</label>
                        <input type="text" id="new_room_name" name="new_room_name" required 
                               pattern="[a-zA-Z0-9_-]{2,50}" 
                               title="Room name must be 2-50 characters and can only contain letters, numbers, hyphens, and underscores">
                    </div>
                    <div class="form-group">
                        <label for="new_room_description">Description</label>
                        <input type="text" id="new_room_description" name="new_room_description" 
                               placeholder="Optional room description">
                    </div>
                    <div class="form-group">
                        <label for="new_room_password">Password (Optional)</label>
                        <input type="password" id="new_room_password" name="new_room_password" 
                               placeholder="Leave empty for public room">
                    </div>
                    <div class="action-buttons">
                        <button type="submit" name="create_room" class="btn btn-success">
                            <i class="fas fa-check"></i> Create Room
                        </button>
                        <button type="button" class="btn btn-secondary" onclick="document.getElementById('create-room-form').style.display='none'">
                            <i class="fas fa-times"></i> Cancel
                        </button>
                    </div>
                </form>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Room Name</th>
                        <th>Description</th>
                        <th>Creator</th>
                        <th>Created</th>
                        <th>Users</th>
                        <th>Messages</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($data as $room): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($room['roomname']); ?></td>
                            <td><?php echo htmlspecialchars($room['description'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($room['creator']); ?></td>
                            <td><?php echo date('M j, Y', strtotime($room['created_at'])); ?></td>
                            <td><?php echo $room['user_count']; ?></td>
                            <td><?php echo $room['message_count']; ?></td>
                            <td>
                                <div class="action-buttons">
                                    <form method="POST">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                        <input type="hidden" name="roomname" value="<?php echo htmlspecialchars($room['roomname']); ?>">
                                        <button type="submit" name="join_room_admin" class="btn btn-success btn-sm">
                                            <i class="fas fa-sign-in-alt"></i> Join
                                        </button>
                                    </form>
                                    <form method="POST" onsubmit="return confirm('Are you sure you want to reset this room? This will delete all messages and files.')">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                        <input type="hidden" name="roomname" value="<?php echo htmlspecialchars($room['roomname']); ?>">
                                        <button type="submit" name="reset_room" class="btn btn-warning btn-sm">
                                            <i class="fas fa-redo"></i> Reset
                                        </button>
                                    </form>
                                    <form method="POST" onsubmit="return confirm('Are you sure you want to permanently delete this room and all its data?')">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                        <input type="hidden" name="roomname" value="<?php echo htmlspecialchars($room['roomname']); ?>">
                                        <button type="submit" name="delete_room" class="btn btn-danger btn-sm">
                                            <i class="fas fa-trash"></i> Delete
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                        <a href="admin.php?tab=rooms&page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) : ''; ?><?php echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : ''; ?>" 
                           class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>

        <!-- Messages Tab -->
        <?php elseif ($active_tab == 'messages'): ?>
            <h2><i class="fas fa-comments"></i> Message Management</h2>
            <p>Total Messages: <?php echo $stats['total_messages']; ?> | Today: <?php echo $stats['today_messages']; ?></p>
            
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Message</th>
                        <th>Room</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($data as $message): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($message['username']); ?></td>
                            <td><?php echo htmlspecialchars(substr($message['msg'], 0, 100)) . (strlen($message['msg']) > 100 ? '...' : ''); ?></td>
                            <td><?php echo htmlspecialchars($message['roomname']); ?></td>
                            <td><?php echo date('M j, Y H:i', strtotime($message['created_at'])); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                        <a href="admin.php?tab=messages&page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) : ''; ?><?php echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : ''; ?>" 
                           class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>

        <!-- Files Tab -->
        <?php elseif ($active_tab == 'files'): ?>
            <h2><i class="fas fa-file"></i> File Management</h2>
            <p>Total Files: <?php echo $stats['total_files']; ?> | Storage Used: <?php echo number_format($stats['storage_used'] / (1024 * 1024), 2); ?> MB</p>
            
            <div class="action-buttons" style="margin-bottom: 1rem;">
                <form method="POST" onsubmit="return confirm('Are you sure you want to delete ALL files? This action cannot be undone.')">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <button type="submit" name="delete_all_files" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Delete All Files
                    </button>
                </form>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Uploaded By</th>
                        <th>Room</th>
                        <th>Uploaded At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($data as $file): ?>
                        <tr>
                            <td>
                                <a href="<?php echo htmlspecialchars($file['filepath']); ?>" class="file-link" target="_blank">
                                    <i class="fas fa-external-link-alt"></i> <?php echo htmlspecialchars($file['filename']); ?>
                                </a>
                            </td>
                            <td><?php echo number_format($file['filesize'] / 1024, 2); ?> KB</td>
                            <td><?php echo htmlspecialchars($file['username']); ?></td>
                            <td><?php echo htmlspecialchars($file['roomname']); ?></td>
                            <td><?php echo date('M j, Y H:i', strtotime($file['uploaded_at'])); ?></td>
                            <td>
                                <form method="POST" onsubmit="return confirm('Are you sure you want to delete this file?')">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                    <input type="hidden" name="file_id" value="<?php echo $file['id']; ?>">
                                    <button type="submit" name="delete_file" class="btn btn-danger btn-sm">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                <div class="pagination">
                    <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                        <a href="admin.php?tab=files&page=<?php echo $i; ?><?php echo !empty($search_query) ? '&search=' . urlencode($search_query) : ''; ?><?php echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : ''; ?>" 
                           class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>
                </div>
        <?php endif; ?>
        <!-- Audit Log Tab -->
        <?php if ($active_tab == 'audit-log'): ?>
            <h2><i class="fas fa-clipboard-list"></i> Audit Log</h2>
            
            <!-- Audit Log Summary -->
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-bottom: 2rem;">
                <?php
                $audit_stats_query = "SELECT 
                    COUNT(*) as total_entries,
                    COUNT(DISTINCT admin_username) as unique_admins,
                    COUNT(DISTINCT DATE(created_at)) as active_days,
                    COUNT(DISTINCT ip_address) as unique_ips
                    FROM admin_audit_log 
                    WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)";
                $audit_stats_result = mysqli_query($conn, $audit_stats_query);
                $audit_stats = mysqli_fetch_assoc($audit_stats_result);
                ?>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['total_entries']; ?></div>
                    <div class="stat-label">Total Entries (30d)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['unique_admins']; ?></div>
                    <div class="stat-label">Unique Admins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['active_days']; ?></div>
                    <div class="stat-label">Active Days</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['unique_ips']; ?></div>
                    <div class="stat-label">Unique IPs</div>
                </div>
            </div>

            <div class="action-buttons" style="margin-bottom: 1.5rem;">
                <form method="POST" onsubmit="return confirm('Are you sure you want to clear the audit log? This action cannot be undone.')">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <button type="submit" name="clear_audit_log" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Clear Audit Log
                    </button>
                </form>
                
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <button type="submit" name="optimize_tables" class="btn btn-info">
                        <i class="fas fa-database"></i> Optimize Database
                    </button>
                </form>
                
                <form method="POST" target="_blank">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <input type="hidden" name="export_type" value="audit">
                    <button type="submit" name="export_data" class="btn btn-success">
                        <i class="fas fa-file-export"></i> Export to CSV
                    </button>
                </form>
                
                <button type="button" class="btn btn-warning" onclick="showAuditSettings()">
                    <i class="fas fa-cog"></i> Settings
                </button>
            </div>

            <!-- Advanced Filters -->
            <div class="card" style="margin-bottom: 1.5rem;">
                <h3><i class="fas fa-filter"></i> Advanced Filters</h3>
                <form method="GET" id="audit-filters">
                    <input type="hidden" name="tab" value="audit-log">
                    
                    <div class="grid-3">
                        <div class="form-group">
                            <label for="date_from">Date From</label>
                            <input type="date" id="date_from" name="date_from" class="form-control" 
                                   value="<?php echo $_GET['date_from'] ?? ''; ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="date_to">Date To</label>
                            <input type="date" id="date_to" name="date_to" class="form-control"
                                   value="<?php echo $_GET['date_to'] ?? ''; ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="action_type">Action Type</label>
                            <select id="action_type" name="action_type" class="form-control">
                                <option value="">All Actions</option>
                                <?php
                                $action_types_query = "SELECT DISTINCT action FROM admin_audit_log ORDER BY action";
                                $action_types_result = mysqli_query($conn, $action_types_query);
                                while ($action_type = mysqli_fetch_assoc($action_types_result)):
                                ?>
                                    <option value="<?php echo htmlspecialchars($action_type['action']); ?>" 
                                            <?php echo ($_GET['action_type'] ?? '') == $action_type['action'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($action_type['action']); ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label for="admin_user">Admin User</label>
                            <select id="admin_user" name="admin_user" class="form-control">
                                <option value="">All Admins</option>
                                <?php
                                $admin_users_query = "SELECT DISTINCT admin_username FROM admin_audit_log ORDER BY admin_username";
                                $admin_users_result = mysqli_query($conn, $admin_users_query);
                                while ($admin_user = mysqli_fetch_assoc($admin_users_result)):
                                ?>
                                    <option value="<?php echo htmlspecialchars($admin_user['admin_username']); ?>" 
                                            <?php echo ($_GET['admin_user'] ?? '') == $admin_user['admin_username'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($admin_user['admin_username']); ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="ip_address">IP Address</label>
                            <input type="text" id="ip_address" name="ip_address" class="form-control"
                                   value="<?php echo htmlspecialchars($_GET['ip_address'] ?? ''); ?>"
                                   placeholder="Enter IP address...">
                        </div>
                    </div>
                    
                    <div class="action-buttons">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Apply Filters
                        </button>
                        <a href="admin.php?tab=audit-log" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Clear Filters
                        </a>
                    </div>
                </form>
            </div>

            <!-- Real-time Activity Monitor -->
            <div class="card" style="margin-bottom: 1.5rem;">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3><i class="fas fa-broadcast-tower"></i> Real-time Activity Monitor</h3>
                    <div class="action-buttons">
                        <button type="button" class="btn btn-success btn-sm" id="start-monitor">
                            <i class="fas fa-play"></i> Start Monitor
                        </button>
                        <button type="button" class="btn btn-danger btn-sm" id="stop-monitor" style="display: none;">
                            <i class="fas fa-stop"></i> Stop Monitor
                        </button>
                    </div>
                </div>
                <div id="activity-feed" style="max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: var(--radius); padding: 1rem;">
                    <div style="text-align: center; color: var(--text-muted); font-style: italic;">
                        Monitor not active. Click "Start Monitor" to begin watching real-time activity.
                    </div>
                </div>
            </div>

            <!-- Audit Log Table -->
            <div class="card">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3>Audit Log Entries</h3>
                    <div style="color: var(--text-muted); font-size: 0.9rem;">
                        Showing <?php echo count($data); ?> of <?php echo $total_rows ?? 0; ?> entries
                    </div>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Admin</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($data as $log): ?>
                            <tr>
                                <td>
                                    <div style="font-size: 0.8rem; font-weight: 600;">
                                        <?php echo date('M j, Y', strtotime($log['created_at'])); ?>
                                    </div>
                                    <div style="font-size: 0.7rem; color: var(--text-muted);">
                                        <?php echo date('H:i:s', strtotime($log['created_at'])); ?>
                                    </div>
                                </td>
                                <td>
                                    <div style="font-weight: 600;"><?php echo htmlspecialchars($log['admin_username']); ?></div>
                                </td>
                                <td>
                                    <span class="badge 
                                        <?php 
                                        if (strpos($log['action'], 'failed') !== false || strpos($log['action'], 'error') !== false) {
                                            echo 'badge-danger';
                                        } elseif (strpos($log['action'], 'success') !== false || strpos($log['action'], 'created') !== false) {
                                            echo 'badge-success';
                                        } elseif (strpos($log['action'], 'warning') !== false) {
                                            echo 'badge-warning';
                                        } else {
                                            echo 'badge-info';
                                        }
                                        ?>">
                                        <?php echo htmlspecialchars($log['action']); ?>
                                    </span>
                                </td>
                                <td>
                                    <div style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" 
                                         title="<?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?>
                                    </div>
                                </td>
                                <td>
                                    <code style="font-size: 0.8rem;"><?php echo htmlspecialchars($log['ip_address']); ?></code>
                                    <button type="button" class="btn btn-sm" onclick="lookupIP('<?php echo $log['ip_address']; ?>')" 
                                            style="padding: 0.1rem 0.3rem; margin-left: 0.25rem; font-size: 0.7rem;">
                                        <i class="fas fa-search"></i>
                                    </button>
                                </td>
                                <td>
                                    <div style="max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.8rem;"
                                         title="<?php echo htmlspecialchars($log['user_agent'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($log['user_agent'] ?? 'N/A'); ?>
                                    </div>
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <button type="button" class="btn btn-info btn-sm view-log-btn" 
                                                data-log-id="<?php echo $log['id'] ?? ''; ?>"
                                                data-log-data="<?php echo htmlspecialchars(json_encode($log), ENT_QUOTES); ?>">
                                            <i class="fas fa-eye"></i> View
                                        </button>
                                        <button type="button" class="btn btn-secondary btn-sm copy-log-btn" 
                                                data-log-data="<?php echo htmlspecialchars(json_encode($log), ENT_QUOTES); ?>">
                                            <i class="fas fa-copy"></i> Copy
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                                <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                    <div class="pagination">
                        <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                            <a href="admin.php?tab=audit-log&page=<?php echo $i; ?><?php 
                                echo !empty($search_query) ? '&search=' . urlencode($search_query) : '';
                                echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : '';
                                echo !empty($_GET['date_from']) ? '&date_from=' . urlencode($_GET['date_from']) : '';
                                echo !empty($_GET['date_to']) ? '&date_to=' . urlencode($_GET['date_to']) : '';
                                echo !empty($_GET['action_type']) ? '&action_type=' . urlencode($_GET['action_type']) : '';
                                echo !empty($_GET['admin_user']) ? '&admin_user=' . urlencode($_GET['admin_user']) : '';
                                echo !empty($_GET['ip_address']) ? '&ip_address=' . urlencode($_GET['ip_address']) : '';
                            ?>" 
                               class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            </div>

    <!-- Log Details Modal -->
    <div id="log-details-modal" class="modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 800px; max-height: 90vh; overflow-y: auto; margin: 20px;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-light);">
                <h3 style="margin: 0;"><i class="fas fa-search"></i> Log Entry Details</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('log-details-modal')" style="border: none; background: rgba(255,255,255,0.1);">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="log-details-content" style="line-height: 1.6;">
                <!-- Content will be populated via JavaScript -->
            </div>
            <div class="action-buttons" style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-light);">
                <button type="button" class="btn btn-secondary" onclick="closeModal('log-details-modal')">
                    <i class="fas fa-times"></i> Close
                </button>
                <button type="button" class="btn btn-primary" onclick="printLogDetails()">
                    <i class="fas fa-print"></i> Print
                </button>
            </div>
        </div>
    </div>

    <!-- Audit Settings Modal -->
    <div id="audit-settings-modal" class="modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 500px; margin: 20px;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-cog"></i> Audit Log Settings</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('audit-settings-modal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                
                <div class="form-group">
                    <label>Auto-clear logs older than:</label>
                    <select name="log_retention" class="form-control">
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                        <option value="365">1 year</option>
                        <option value="0">Never (not recommended)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="log_ip_geolocation" value="1"> Enable IP geolocation
                    </label>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="log_user_agent_parsing" value="1"> Enable user agent parsing
                    </label>
                </div>
                
                <div class="action-buttons">
                    <button type="submit" name="save_audit_settings" class="btn btn-success">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal('audit-settings-modal')">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>

                <!-- Admin Management Tab -->
        <?php elseif ($active_tab == 'admin-management' && $current_admin_role === 'master'): ?>
            <h2><i class="fas fa-user-shield"></i> Admin Management</h2>
            
            <!-- Quick Stats -->
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-bottom: 2rem;">
                <?php
                $admin_stats_query = "SELECT 
                    COUNT(*) as total_admins,
                    SUM(is_active = 1) as active_admins,
                    SUM(role = 'master') as master_admins,
                    SUM(last_login > DATE_SUB(NOW(), INTERVAL 7 DAY)) as recent_logins
                    FROM admin_users";
                $admin_stats_result = mysqli_query($conn, $admin_stats_query);
                $admin_stats = mysqli_fetch_assoc($admin_stats_result);
                ?>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $admin_stats['total_admins']; ?></div>
                    <div class="stat-label">Total Admins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $admin_stats['active_admins']; ?></div>
                    <div class="stat-label">Active Admins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $admin_stats['master_admins']; ?></div>
                    <div class="stat-label">Master Admins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $admin_stats['recent_logins']; ?></div>
                    <div class="stat-label">Recent Logins (7d)</div>
                </div>
            </div>

            <div class="grid-2">
                <!-- Add New Admin -->
                <div class="card">
                    <div class="card-header" style="display: flex; justify-content: between; align-items: center; margin-bottom: 1.5rem;">
                        <h3><i class="fas fa-user-plus"></i> Add New Admin</h3>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="togglePasswordGenerator()">
                            <i class="fas fa-key"></i> Generate Password
                        </button>
                    </div>
                    <form method="POST" id="admin-form">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        
                        <div class="form-group">
                            <label for="new_admin_username">Username *</label>
                            <input type="text" id="new_admin_username" name="new_admin_username" required 
                                   pattern="[a-zA-Z0-9_-]{3,30}" 
                                   title="Username must be 3-30 characters and can only contain letters, numbers, hyphens, and underscores"
                                   onblur="checkUsernameAvailability(this.value)">
                            <div id="username-availability" style="font-size: 0.8rem; margin-top: 0.25rem;"></div>
                        </div>
                        
                        <div class="form-group">
                            <label for="new_admin_email">Email *</label>
                            <input type="email" id="new_admin_email" name="new_admin_email" required
                                   onblur="validateEmail(this.value)">
                            <div id="email-validation" style="font-size: 0.8rem; margin-top: 0.25rem;"></div>
                        </div>
                        
                        <div class="form-group">
                            <label for="new_admin_role">Role</label>
                            <select id="new_admin_role" name="new_admin_role" class="form-control">
                                <option value="admin">Admin</option>
                                <option value="master">Master Admin</option>
                            </select>
                            <small style="color: var(--text-muted); font-size: 0.8rem;">
                                Master admins have full system access including admin management
                            </small>
                        </div>
                        
                        <div class="form-group">
                            <label for="new_admin_password">Password *</label>
                            <div style="position: relative;">
                                <input type="password" id="new_admin_password" name="new_admin_password" required
                                       pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).{8,}"
                                       oninput="checkPasswordStrength(this.value)">
                                <button type="button" class="password-toggle" onclick="togglePasswordVisibility('new_admin_password')" 
                                        style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-light); cursor: pointer;">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                            <div id="password-strength" style="margin-top: 0.5rem;">
                                <div style="display: flex; gap: 0.25rem; margin-bottom: 0.25rem;">
                                    <div id="strength-bar-1" style="flex: 1; height: 4px; background: var(--border-light); border-radius: 2px;"></div>
                                    <div id="strength-bar-2" style="flex: 1; height: 4px; background: var(--border-light); border-radius: 2px;"></div>
                                    <div id="strength-bar-3" style="flex: 1; height: 4px; background: var(--border-light); border-radius: 2px;"></div>
                                    <div id="strength-bar-4" style="flex: 1; height: 4px; background: var(--border-light); border-radius: 2px;"></div>
                                </div>
                                <div id="password-feedback" style="font-size: 0.8rem;"></div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="confirm_admin_password">Confirm Password *</label>
                            <div style="position: relative;">
                                <input type="password" id="confirm_admin_password" name="confirm_admin_password" required
                                       oninput="checkPasswordMatch()">
                                <button type="button" class="password-toggle" onclick="togglePasswordVisibility('confirm_admin_password')"
                                        style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-light); cursor: pointer;">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                            <div id="password-match" style="font-size: 0.8rem; margin-top: 0.25rem;"></div>
                        </div>

                        <!-- Password Generator -->
                        <div id="password-generator" class="card" style="display: none; margin-bottom: 1rem; background: rgba(15, 23, 42, 0.4);">
                            <h4 style="margin-bottom: 1rem;"><i class="fas fa-magic"></i> Password Generator</h4>
                            <div class="form-group">
                                <label>Password Length: <span id="length-value">12</span></label>
                                <input type="range" id="password-length" min="8" max="20" value="12" style="width: 100%;">
                            </div>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-bottom: 1rem;">
                                <label style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="checkbox" id="include-uppercase" checked> Uppercase
                                </label>
                                <label style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="checkbox" id="include-lowercase" checked> Lowercase
                                </label>
                                <label style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="checkbox" id="include-numbers" checked> Numbers
                                </label>
                                <label style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="checkbox" id="include-symbols" checked> Symbols
                                </label>
                            </div>
                            <div class="action-buttons">
                                <button type="button" class="btn btn-secondary btn-sm" onclick="generatePassword()">
                                    <i class="fas fa-sync"></i> Generate
                                </button>
                                <button type="button" class="btn btn-primary btn-sm" onclick="useGeneratedPassword()">
                                    <i class="fas fa-check"></i> Use This Password
                                </button>
                            </div>
                            <div id="generated-password" style="margin-top: 1rem; padding: 0.75rem; background: rgba(255,255,255,0.1); border-radius: var(--radius); font-family: monospace; text-align: center;"></div>
                        </div>
                        
                        <div class="action-buttons">
                            <button type="submit" name="add_admin" class="btn btn-success" id="submit-admin-btn">
                                <i class="fas fa-plus"></i> Create Admin
                            </button>
                            <button type="reset" class="btn btn-secondary" onclick="resetAdminForm()">
                                <i class="fas fa-redo"></i> Reset Form
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Current Admins -->
                <div class="card">
                    <div class="card-header" style="display: flex; justify-content: between; align-items: center; margin-bottom: 1.5rem;">
                        <h3><i class="fas fa-users-cog"></i> Current Admins</h3>
                        <div class="action-buttons">
                            <button type="button" class="btn btn-info btn-sm" onclick="exportAdminList()">
                                <i class="fas fa-download"></i> Export
                            </button>
                            <button type="button" class="btn btn-secondary btn-sm" onclick="refreshAdminList()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                        </div>
                    </div>
                    
                    <!-- Admin Filters -->
                    <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap;">
                        <button type="button" class="btn btn-sm <?php echo empty($_GET['admin_filter']) ? 'btn-primary' : 'btn-secondary'; ?>" 
                                onclick="filterAdmins('')">All</button>
                        <button type="button" class="btn btn-sm <?php echo $_GET['admin_filter'] == 'active' ? 'btn-primary' : 'btn-secondary'; ?>" 
                                onclick="filterAdmins('active')">Active</button>
                        <button type="button" class="btn btn-sm <?php echo $_GET['admin_filter'] == 'inactive' ? 'btn-primary' : 'btn-secondary'; ?>" 
                                onclick="filterAdmins('inactive')">Inactive</button>
                        <button type="button" class="btn btn-sm <?php echo $_GET['admin_filter'] == 'master' ? 'btn-primary' : 'btn-secondary'; ?>" 
                                onclick="filterAdmins('master')">Master</button>
                        <button type="button" class="btn btn-sm <?php echo $_GET['admin_filter'] == 'recent' ? 'btn-primary' : 'btn-secondary'; ?>" 
                                onclick="filterAdmins('recent')">Recent</button>
                    </div>
                    
                    <div id="admin-list" style="max-height: 500px; overflow-y: auto;">
                        <?php
                        $admin_filter = $_GET['admin_filter'] ?? '';
                        $admin_where = "";
                        switch($admin_filter) {
                            case 'active': $admin_where = "WHERE is_active = 1"; break;
                            case 'inactive': $admin_where = "WHERE is_active = 0"; break;
                            case 'master': $admin_where = "WHERE role = 'master'"; break;
                            case 'recent': $admin_where = "WHERE last_login > DATE_SUB(NOW(), INTERVAL 7 DAY)"; break;
                        }
                        
                        $admin_query = "SELECT id, username, email, role, is_active, created_at, last_login, 
                                       (SELECT COUNT(*) FROM admin_audit_log WHERE admin_username = admin_users.username) as action_count
                                FROM admin_users 
                                $admin_where 
                                ORDER BY created_at DESC";
                        $admin_result = mysqli_query($conn, $admin_query);

                        if ($admin_result && mysqli_num_rows($admin_result) > 0):
                            while ($admin = mysqli_fetch_assoc($admin)):
                        ?>
                            <div class="admin-item" style="padding: 1rem; border-bottom: 1px solid var(--border-light); display: flex; justify-content: space-between; align-items: center; transition: var(--transition);">
                                <div style="flex: 1;">
                                    <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem;">
                                        <strong><?php echo htmlspecialchars($admin['username']); ?></strong>
                                        <?php if ($admin['role'] === 'master'): ?>
                                            <span class="badge badge-primary">MASTER</span>
                                        <?php endif; ?>
                                        <?php if (!$admin['is_active']): ?>
                                            <span class="badge badge-danger">INACTIVE</span>
                                        <?php endif; ?>
                                    </div>
                                    <div style="font-size: 0.8rem; color: var(--text-light); line-height: 1.4;">
                                        <div><?php echo htmlspecialchars($admin['email']); ?></div>
                                        <div>
                                            Created: <?php echo date('M j, Y', strtotime($admin['created_at'])); ?> | 
                                            Last Login: <?php echo $admin['last_login'] ? date('M j, Y H:i', strtotime($admin['last_login'])) : 'Never'; ?> |
                                            Actions: <?php echo $admin['action_count']; ?>
                                        </div>
                                    </div>
                                </div>
                                <div class="action-buttons">
                                    <?php if ($admin['username'] !== $_SESSION['admin_username'] && $admin['role'] !== 'master'): ?>
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                            <input type="hidden" name="admin_id" value="<?php echo $admin['id']; ?>">
                                            <input type="hidden" name="action" value="<?php echo $admin['is_active'] ? 'deactivate' : 'activate'; ?>">
                                            <button type="submit" name="toggle_admin_status" class="btn <?php echo $admin['is_active'] ? 'btn-warning' : 'btn-success'; ?> btn-sm">
                                                <i class="fas fa-<?php echo $admin['is_active'] ? 'ban' : 'check'; ?>"></i>
                                                <?php echo $admin['is_active'] ? 'Deactivate' : 'Activate'; ?>
                                            </button>
                                        </form>
                                        <button type="button" class="btn btn-info btn-sm" onclick="showAdminDetails(<?php echo $admin['id']; ?>)">
                                            <i class="fas fa-info-circle"></i> Details
                                        </button>
                                        <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to permanently delete this admin? This will also remove all their audit logs.')">
                                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                            <input type="hidden" name="admin_id" value="<?php echo $admin['id']; ?>">
                                            <button type="submit" name="delete_admin" class="btn btn-danger btn-sm">
                                                <i class="fas fa-trash"></i> Delete
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <span class="badge badge-info" style="font-size: 0.7rem;">
                                            <?php echo $admin['username'] === $_SESSION['admin_username'] ? 'Current User' : 'Protected'; ?>
                                        </span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php
                            endwhile;
                        else:
                            echo '<div style="text-align: center; padding: 2rem; color: var(--text-muted);">No admin users found.</div>';
                        endif;
                        ?>
                    </div>
                </div>
            </div>

            <!-- Admin Activity Report -->
            <div class="card">
                <h3><i class="fas fa-chart-bar"></i> Admin Activity Report</h3>
                <div class="grid-3">
                    <?php
                    $activity_report_query = "
                        SELECT 
                            COUNT(*) as total_actions,
                            COUNT(DISTINCT admin_username) as active_admins,
                            AVG(TIMESTAMPDIFF(MINUTE, created_at, NOW())) as avg_minutes_ago,
                            MAX(created_at) as latest_action
                        FROM admin_audit_log 
                        WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
                    ";
                    $activity_result = mysqli_query($conn, $activity_report_query);
                    $activity_data = mysqli_fetch_assoc($activity_result);
                    
                    $top_actions_query = "
                        SELECT action, COUNT(*) as count 
                        FROM admin_audit_log 
                        WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
                        GROUP BY action 
                        ORDER BY count DESC 
                        LIMIT 5
                    ";
                    $top_actions_result = mysqli_query($conn, $top_actions_query);
                    ?>
                    
                    <div class="health-item">
                        <div class="health-value"><?php echo $activity_data['total_actions'] ?? 0; ?></div>
                        <div class="health-label">Actions (7 days)</div>
                    </div>
                    <div class="health-item">
                        <div class="health-value"><?php echo $activity_data['active_admins'] ?? 0; ?></div>
                        <div class="health-label">Active Admins</div>
                    </div>
                    <div class="health-item">
                        <div class="health-value"><?php echo $activity_data['avg_minutes_ago'] ? round($activity_data['avg_minutes_ago']) . 'm' : 'N/A'; ?></div>
                        <div class="health-label">Avg. Time Since Action</div>
                    </div>
                </div>
                
                <div style="margin-top: 1.5rem;">
                    <h4 style="margin-bottom: 1rem;">Top Actions This Week</h4>
                    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                        <?php while ($action = mysqli_fetch_assoc($top_actions_result)): ?>
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(255,255,255,0.05); border-radius: var(--radius);">
                                <span style="font-size: 0.9rem;"><?php echo htmlspecialchars($action['action']); ?></span>
                                <span class="badge badge-primary"><?php echo $action['count']; ?></span>
                            </div>
                        <?php endwhile; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        <!-- Audit Log Tab -->
        <?php elseif ($active_tab == 'audit-log'): ?>
            <h2><i class="fas fa-clipboard-list"></i> Audit Log</h2>
            
            <!-- Audit Log Summary -->
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-bottom: 2rem;">
                <?php
                $audit_stats_query = "SELECT 
                    COUNT(*) as total_entries,
                    COUNT(DISTINCT admin_username) as unique_admins,
                    COUNT(DISTINCT DATE(created_at)) as active_days,
                    COUNT(DISTINCT ip_address) as unique_ips
                    FROM admin_audit_log 
                    WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)";
                $audit_stats_result = mysqli_query($conn, $audit_stats_query);
                $audit_stats = mysqli_fetch_assoc($audit_stats_result);
                ?>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['total_entries']; ?></div>
                    <div class="stat-label">Total Entries (30d)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['unique_admins']; ?></div>
                    <div class="stat-label">Unique Admins</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['active_days']; ?></div>
                    <div class="stat-label">Active Days</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $audit_stats['unique_ips']; ?></div>
                    <div class="stat-label">Unique IPs</div>
                </div>
            </div>

            <div class="action-buttons" style="margin-bottom: 1.5rem;">
                <form method="POST" onsubmit="return confirm('Are you sure you want to clear the audit log? This action cannot be undone.')">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <button type="submit" name="clear_audit_log" class="btn btn-danger">
                        <i class="fas fa-trash"></i> Clear Audit Log
                    </button>
                </form>
                
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <button type="submit" name="optimize_tables" class="btn btn-info">
                        <i class="fas fa-database"></i> Optimize Database
                    </button>
                </form>
                
                <form method="POST" target="_blank">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                    <input type="hidden" name="export_type" value="audit">
                    <button type="submit" name="export_data" class="btn btn-success">
                        <i class="fas fa-file-export"></i> Export to CSV
                    </button>
                </form>
                
                <button type="button" class="btn btn-warning" onclick="showAuditSettings()">
                    <i class="fas fa-cog"></i> Settings
                </button>
            </div>

            <!-- Advanced Filters -->
            <div class="card" style="margin-bottom: 1.5rem;">
                <h3><i class="fas fa-filter"></i> Advanced Filters</h3>
                <form method="GET" id="audit-filters">
                    <input type="hidden" name="tab" value="audit-log">
                    
                    <div class="grid-3">
                        <div class="form-group">
                            <label for="date_from">Date From</label>
                            <input type="date" id="date_from" name="date_from" class="form-control" 
                                   value="<?php echo $_GET['date_from'] ?? ''; ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="date_to">Date To</label>
                            <input type="date" id="date_to" name="date_to" class="form-control"
                                   value="<?php echo $_GET['date_to'] ?? ''; ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="action_type">Action Type</label>
                            <select id="action_type" name="action_type" class="form-control">
                                <option value="">All Actions</option>
                                <?php
                                $action_types_query = "SELECT DISTINCT action FROM admin_audit_log ORDER BY action";
                                $action_types_result = mysqli_query($conn, $action_types_query);
                                while ($action_type = mysqli_fetch_assoc($action_types_result)):
                                ?>
                                    <option value="<?php echo htmlspecialchars($action_type['action']); ?>" 
                                            <?php echo ($_GET['action_type'] ?? '') == $action_type['action'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($action_type['action']); ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                    </div>
                    
                    <div class="grid-2">
                        <div class="form-group">
                            <label for="admin_user">Admin User</label>
                            <select id="admin_user" name="admin_user" class="form-control">
                                <option value="">All Admins</option>
                                <?php
                                $admin_users_query = "SELECT DISTINCT admin_username FROM admin_audit_log ORDER BY admin_username";
                                $admin_users_result = mysqli_query($conn, $admin_users_query);
                                while ($admin_user = mysqli_fetch_assoc($admin_users_result)):
                                ?>
                                    <option value="<?php echo htmlspecialchars($admin_user['admin_username']); ?>" 
                                            <?php echo ($_GET['admin_user'] ?? '') == $admin_user['admin_username'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($admin_user['admin_username']); ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="ip_address">IP Address</label>
                            <input type="text" id="ip_address" name="ip_address" class="form-control"
                                   value="<?php echo htmlspecialchars($_GET['ip_address'] ?? ''); ?>"
                                   placeholder="Enter IP address...">
                        </div>
                    </div>
                    
                    <div class="action-buttons">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Apply Filters
                        </button>
                        <a href="admin.php?tab=audit-log" class="btn btn-secondary">
                            <i class="fas fa-times"></i> Clear Filters
                        </a>
                    </div>
                </form>
            </div>

            <!-- Real-time Activity Monitor -->
            <div class="card" style="margin-bottom: 1.5rem;">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center;">
                    <h3><i class="fas fa-broadcast-tower"></i> Real-time Activity Monitor</h3>
                    <div class="action-buttons">
                        <button type="button" class="btn btn-success btn-sm" id="start-monitor">
                            <i class="fas fa-play"></i> Start Monitor
                        </button>
                        <button type="button" class="btn btn-danger btn-sm" id="stop-monitor" style="display: none;">
                            <i class="fas fa-stop"></i> Stop Monitor
                        </button>
                    </div>
                </div>
                <div id="activity-feed" style="max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: var(--radius); padding: 1rem;">
                    <div style="text-align: center; color: var(--text-muted); font-style: italic;">
                        Monitor not active. Click "Start Monitor" to begin watching real-time activity.
                    </div>
                </div>
            </div>

            <!-- Audit Log Table -->
            <div class="card">
                <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                    <h3>Audit Log Entries</h3>
                    <div style="color: var(--text-muted); font-size: 0.9rem;">
                        Showing <?php echo count($data); ?> of <?php echo $total_rows ?? 0; ?> entries
                    </div>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Admin</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($data as $log): ?>
                            <tr>
                                <td>
                                    <div style="font-size: 0.8rem; font-weight: 600;">
                                        <?php echo date('M j, Y', strtotime($log['created_at'])); ?>
                                    </div>
                                    <div style="font-size: 0.7rem; color: var(--text-muted);">
                                        <?php echo date('H:i:s', strtotime($log['created_at'])); ?>
                                    </div>
                                </td>
                                <td>
                                    <div style="font-weight: 600;"><?php echo htmlspecialchars($log['admin_username']); ?></div>
                                </td>
                                <td>
                                    <span class="badge 
                                        <?php 
                                        if (strpos($log['action'], 'failed') !== false || strpos($log['action'], 'error') !== false) {
                                            echo 'badge-danger';
                                        } elseif (strpos($log['action'], 'success') !== false || strpos($log['action'], 'created') !== false) {
                                            echo 'badge-success';
                                        } elseif (strpos($log['action'], 'warning') !== false) {
                                            echo 'badge-warning';
                                        } else {
                                            echo 'badge-info';
                                        }
                                        ?>">
                                        <?php echo htmlspecialchars($log['action']); ?>
                                    </span>
                                </td>
                                <td>
                                    <div style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" 
                                         title="<?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?>
                                    </div>
                                </td>
                                <td>
                                    <code style="font-size: 0.8rem;"><?php echo htmlspecialchars($log['ip_address']); ?></code>
                                    <button type="button" class="btn btn-sm" onclick="lookupIP('<?php echo $log['ip_address']; ?>')" 
                                            style="padding: 0.1rem 0.3rem; margin-left: 0.25rem; font-size: 0.7rem;">
                                        <i class="fas fa-search"></i>
                                    </button>
                                </td>
                                <td>
                                    <div style="max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.8rem;"
                                         title="<?php echo htmlspecialchars($log['user_agent'] ?? 'N/A'); ?>">
                                        <?php echo htmlspecialchars($log['user_agent'] ?? 'N/A'); ?>
                                    </div>
                                </td>
                                <td>
                                    <div class="action-buttons">
                                        <button type="button" class="btn btn-info btn-sm" 
                                                onclick="showLogDetails(<?php echo htmlspecialchars(json_encode($log)); ?>)">
                                            <i class="fas fa-eye"></i> View
                                        </button>
                                        <button type="button" class="btn btn-secondary btn-sm" 
                                                onclick="copyToClipboard('<?php echo addslashes(json_encode($log)); ?>')">
                                            <i class="fas fa-copy"></i> Copy
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <?php if (!empty($pagination) && $pagination['total_pages'] > 1): ?>
                    <div class="pagination">
                        <?php for ($i = 1; $i <= $pagination['total_pages']; $i++): ?>
                            <a href="admin.php?tab=audit-log&page=<?php echo $i; ?><?php 
                                echo !empty($search_query) ? '&search=' . urlencode($search_query) : '';
                                echo !empty($filter_type) ? '&filter=' . urlencode($filter_type) : '';
                                echo !empty($_GET['date_from']) ? '&date_from=' . urlencode($_GET['date_from']) : '';
                                echo !empty($_GET['date_to']) ? '&date_to=' . urlencode($_GET['date_to']) : '';
                                echo !empty($_GET['action_type']) ? '&action_type=' . urlencode($_GET['action_type']) : '';
                                echo !empty($_GET['admin_user']) ? '&admin_user=' . urlencode($_GET['admin_user']) : '';
                                echo !empty($_GET['ip_address']) ? '&ip_address=' . urlencode($_GET['ip_address']) : '';
                            ?>" 
                               class="<?php echo $i == $pagination['page'] ? 'current' : ''; ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            </div>

        <?php endif; ?>

    </div>

    <!-- Admin Details Modal -->
    <div id="admin-details-modal" class="modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 600px; max-height: 80vh; overflow-y: auto;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-user-cog"></i> Admin Details</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('admin-details-modal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="admin-details-content">
                <!-- Content will be loaded via AJAX -->
            </div>
        </div>
    </div>


    <!-- Log Details Modal -->
    <div id="log-details-modal" class="modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 800px; max-height: 80vh; overflow-y: auto;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-search"></i> Log Entry Details</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('log-details-modal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="log-details-content">
                <!-- Content will be populated via JavaScript -->
            </div>
        </div>
    </div>

    <!-- Audit Settings Modal -->
    <div id="audit-settings-modal" class="modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 1000; align-items: center; justify-content: center;">
        <div class="card" style="max-width: 500px;">
            <div class="card-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h3><i class="fas fa-cog"></i> Audit Log Settings</h3>
                <button type="button" class="btn btn-secondary btn-sm" onclick="closeModal('audit-settings-modal')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                
                <div class="form-group">
                    <label>Auto-clear logs older than:</label>
                    <select name="log_retention" class="form-control">
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                        <option value="365">1 year</option>
                        <option value="0">Never (not recommended)</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="log_ip_geolocation" value="1"> Enable IP geolocation
                    </label>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="log_user_agent_parsing" value="1"> Enable user agent parsing
                    </label>
                </div>
                
                <div class="action-buttons">
                    <button type="submit" name="save_audit_settings" class="btn btn-success">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="closeModal('audit-settings-modal')">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>
    </div>
<script>
        // Enhanced JavaScript for Admin Management and Audit Log
        let activityMonitorInterval;
        
        // Password strength checker
        function checkPasswordStrength(password) {
            const strengthBars = [
                document.getElementById('strength-bar-1'),
                document.getElementById('strength-bar-2'),
                document.getElementById('strength-bar-3'),
                document.getElementById('strength-bar-4')
            ];
            
            const feedback = document.getElementById('password-feedback');
            let strength = 0;
            let messages = [];
            
            // Reset bars
            strengthBars.forEach(bar => bar.style.background = 'var(--border-light)');
            
            if (password.length >= 8) strength++;
            if (password.match(/[a-z]/)) strength++;
            if (password.match(/[A-Z]/)) strength++;
            if (password.match(/[0-9]/)) strength++;
            if (password.match(/[!@#$%^&*()\-_=+{};:,<.>]/)) strength++;
            
            // Update visual feedback
            for (let i = 0; i < strength; i++) {
                if (i < 2) {
                    strengthBars[i].style.background = 'var(--danger)';
                } else if (i < 4) {
                    strengthBars[i].style.background = 'var(--warning)';
                } else {
                    strengthBars[i].style.background = 'var(--success)';
                }
            }
            
            // Text feedback
            if (password.length === 0) {
                feedback.innerHTML = '';
            } else if (strength <= 2) {
                feedback.innerHTML = '<span style="color: var(--danger);">Weak password</span>';
            } else if (strength <= 4) {
                feedback.innerHTML = '<span style="color: var(--warning);">Medium strength</span>';
            } else {
                feedback.innerHTML = '<span style="color: var(--success);">Strong password</span>';
            }
        }
        
        // Password match checker
        function checkPasswordMatch() {
            const password = document.getElementById('new_admin_password').value;
            const confirmPassword = document.getElementById('confirm_admin_password').value;
            const matchDiv = document.getElementById('password-match');
            
            if (confirmPassword.length === 0) {
                matchDiv.innerHTML = '';
            } else if (password === confirmPassword) {
                matchDiv.innerHTML = '<span style="color: var(--success);"><i class="fas fa-check"></i> Passwords match</span>';
            } else {
                matchDiv.innerHTML = '<span style="color: var(--danger);"><i class="fas fa-times"></i> Passwords do not match</span>';
            }
        }
        
        // Username availability check
        function checkUsernameAvailability(username) {
            if (username.length < 3) return;
            
            const availabilityDiv = document.getElementById('username-availability');
            availabilityDiv.innerHTML = '<span style="color: var(--warning);"><i class="fas fa-spinner fa-spin"></i> Checking...</span>';
            
            // Simulate AJAX check - in real implementation, this would be an AJAX call
            setTimeout(() => {
                // This is a simulation - replace with actual AJAX call
                const takenUsernames = ['admin', 'superuser', 'moderator']; // Example taken usernames
                if (takenUsernames.includes(username.toLowerCase())) {
                    availabilityDiv.innerHTML = '<span style="color: var(--danger);"><i class="fas fa-times"></i> Username already taken</span>';
                } else {
                    availabilityDiv.innerHTML = '<span style="color: var(--success);"><i class="fas fa-check"></i> Username available</span>';
                }
            }, 1000);
        }
        
        // Email validation
        function validateEmail(email) {
            const validationDiv = document.getElementById('email-validation');
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            
            if (email.length === 0) {
                validationDiv.innerHTML = '';
            } else if (emailRegex.test(email)) {
                validationDiv.innerHTML = '<span style="color: var(--success);"><i class="fas fa-check"></i> Valid email format</span>';
            } else {
                validationDiv.innerHTML = '<span style="color: var(--danger);"><i class="fas fa-times"></i> Invalid email format</span>';
            }
        }
        
        // Password generator
        function togglePasswordGenerator() {
            const generator = document.getElementById('password-generator');
            generator.style.display = generator.style.display === 'none' ? 'block' : 'none';
        }
        
        function generatePassword() {
            const length = parseInt(document.getElementById('password-length').value);
            const includeUpper = document.getElementById('include-uppercase').checked;
            const includeLower = document.getElementById('include-lowercase').checked;
            const includeNumbers = document.getElementById('include-numbers').checked;
            const includeSymbols = document.getElementById('include-symbols').checked;
            
            const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
            const numberChars = '0123456789';
            const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
            
            let allChars = '';
            if (includeUpper) allChars += upperChars;
            if (includeLower) allChars += lowerChars;
            if (includeNumbers) allChars += numberChars;
            if (includeSymbols) allChars += symbolChars;
            
            if (allChars === '') {
                alert('Please select at least one character type');
                return;
            }
            
            let password = '';
            for (let i = 0; i < length; i++) {
                password += allChars.charAt(Math.floor(Math.random() * allChars.length));
            }
            
            document.getElementById('generated-password').textContent = password;
        }
        
        function useGeneratedPassword() {
            const generatedPassword = document.getElementById('generated-password').textContent;
            if (generatedPassword) {
                document.getElementById('new_admin_password').value = generatedPassword;
                document.getElementById('confirm_admin_password').value = generatedPassword;
                checkPasswordStrength(generatedPassword);
                checkPasswordMatch();
                togglePasswordGenerator();
            }
        }
        
        // Password visibility toggle
        function togglePasswordVisibility(fieldId) {
            const field = document.getElementById(fieldId);
            const toggle = field.parentNode.querySelector('.password-toggle i');
            
            if (field.type === 'password') {
                field.type = 'text';
                toggle.className = 'fas fa-eye-slash';
            } else {
                field.type = 'password';
                toggle.className = 'fas fa-eye';
            }
        }
        
        // Admin list filtering
        function filterAdmins(filter) {
            window.location.href = `admin.php?tab=admin-management&admin_filter=${filter}`;
        }
        
        // Export admin list
        function exportAdminList() {
            // In real implementation, this would trigger a CSV export
            alert('Exporting admin list to CSV...');
        }
        
        // Refresh admin list
        function refreshAdminList() {
            window.location.reload();
        }
        
        // Show admin details
        function showAdminDetails(adminId) {
            // In real implementation, this would fetch admin details via AJAX
            const modal = document.getElementById('admin-details-modal');
            const content = document.getElementById('admin-details-content');
            
            content.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <i class="fas fa-spinner fa-spin fa-2x" style="color: var(--primary);"></i>
                    <div style="margin-top: 1rem;">Loading admin details...</div>
                </div>
            `;
            
            modal.style.display = 'flex';
            
            // Simulate AJAX loading
            setTimeout(() => {
                content.innerHTML = `
                    <div class="grid-2">
                        <div>
                            <strong>Username:</strong><br>
                            <span>admin_${adminId}</span>
                        </div>
                        <div>
                            <strong>Role:</strong><br>
                            <span class="badge badge-primary">Admin</span>
                        </div>
                        <div>
                            <strong>Status:</strong><br>
                            <span class="badge badge-success">Active</span>
                        </div>
                        <div>
                            <strong>Last Login:</strong><br>
                            <span>${new Date().toLocaleString()}</span>
                        </div>
                    </div>
                    <div style="margin-top: 1.5rem;">
                        <h4>Recent Activity</h4>
                        <div style="max-height: 200px; overflow-y: auto;">
                            <div style="padding: 0.5rem; border-bottom: 1px solid var(--border-light);">
                                <div>User login</div>
                                <small style="color: var(--text-muted);">2 hours ago</small>
                            </div>
                            <div style="padding: 0.5rem; border-bottom: 1px solid var(--border-light);">
                                <div>Room created</div>
                                <small style="color: var(--text-muted);">5 hours ago</small>
                            </div>
                        </div>
                    </div>
                `;
            }, 1000);
        }
        
        // Audit log functions
        function showLogDetails(log) {
            const modal = document.getElementById('log-details-modal');
            const content = document.getElementById('log-details-content');
            
            try {
                const logData = typeof log === 'string' ? JSON.parse(log) : log;
                
                content.innerHTML = `
                    <div class="grid-2">
                        <div>
                            <strong>Timestamp:</strong><br>
                            <span>${new Date(logData.created_at).toLocaleString()}</span>
                        </div>
                        <div>
                            <strong>Admin:</strong><br>
                            <span>${logData.admin_username}</span>
                        </div>
                        <div>
                            <strong>Action:</strong><br>
                            <span class="badge badge-info">${logData.action}</span>
                        </div>
                        <div>
                            <strong>IP Address:</strong><br>
                            <code>${logData.ip_address}</code>
                        </div>
                    </div>
                    <div style="margin-top: 1.5rem;">
                        <strong>Details:</strong><br>
                        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: var(--radius); margin-top: 0.5rem; font-family: monospace; white-space: pre-wrap;">
                            ${logData.details || 'No details provided'}
                        </div>
                    </div>
                    <div style="margin-top: 1.5rem;">
                        <strong>User Agent:</strong><br>
                        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: var(--radius); margin-top: 0.5rem; font-size: 0.8rem;">
                            ${logData.user_agent || 'Not available'}
                        </div>
                    </div>
                `;
                
                modal.style.display = 'flex';
            } catch (e) {
                alert('Error displaying log details: ' + e.message);
            }
        }
        
        function lookupIP(ip) {
            window.open(`https://whatismyipaddress.com/ip/${ip}`, '_blank');
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Show success message
                const originalText = event.target.innerHTML;
                event.target.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => {
                    event.target.innerHTML = originalText;
                }, 2000);
            });
        }
        
        function showAuditSettings() {
            document.getElementById('audit-settings-modal').style.display = 'flex';
        }
        
        // Real-time activity monitor
        document.getElementById('start-monitor').addEventListener('click', function() {
            const feed = document.getElementById('activity-feed');
            this.style.display = 'none';
            document.getElementById('stop-monitor').style.display = 'inline-block';
            
            feed.innerHTML = '<div style="text-align: center; color: var(--success);"><i class="fas fa-circle" style="color: var(--success);"></i> Monitoring started...</div>';
            
            // Simulate real-time updates
            activityMonitorInterval = setInterval(() => {
                const now = new Date();
                const timeString = now.toLocaleTimeString();
                
                // Simulate new activity
                const activities = [
                    `${timeString} - admin_user logged in from 192.168.1.100`,
                    `${timeString} - super_admin created new room "General Chat"`,
                    `${timeString} - moderator deleted user spam_account`,
                    `${timeString} - admin_user exported user list`
                ];
                
                const randomActivity = activities[Math.floor(Math.random() * activities.length)];
                
                const activityItem = document.createElement('div');
                activityItem.style.padding = '0.5rem';
                activityItem.style.borderBottom = '1px solid var(--border-light)';
                activityItem.style.fontSize = '0.8rem';
                activityItem.innerHTML = `<i class="fas fa-circle" style="color: var(--success); font-size: 0.5rem;"></i> ${randomActivity}`;
                
                feed.insertBefore(activityItem, feed.firstChild);
                
                // Keep only last 10 items
                while (feed.children.length > 10) {
                    feed.removeChild(feed.lastChild);
                }
            }, 3000);
        });
        
        document.getElementById('stop-monitor').addEventListener('click', function() {
            this.style.display = 'none';
            document.getElementById('start-monitor').style.display = 'inline-block';
            clearInterval(activityMonitorInterval);
            
            document.getElementById('activity-feed').innerHTML = 
                '<div style="text-align: center; color: var(--text-muted); font-style: italic;">Monitor stopped.</div>';
        });
        
        // Modal close function
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        
        // Close modals when clicking outside
        window.addEventListener('click', function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        });
        
        // Form reset
        function resetAdminForm() {
            document.getElementById('admin-form').reset();
            document.getElementById('username-availability').innerHTML = '';
            document.getElementById('email-validation').innerHTML = '';
            document.getElementById('password-feedback').innerHTML = '';
            document.getElementById('password-match').innerHTML = '';
            
            // Reset strength bars
            const strengthBars = ['strength-bar-1', 'strength-bar-2', 'strength-bar-3', 'strength-bar-4'];
            strengthBars.forEach(id => {
                document.getElementById(id).style.background = 'var(--border-light)';
            });
        }
        
        // Initialize password length display
        document.getElementById('password-length').addEventListener('input', function() {
            document.getElementById('length-value').textContent = this.value;
        });
        
        // Auto-generate password on load
        document.addEventListener('DOMContentLoaded', function() {
            generatePassword();
        });
    </script>
    <script>
        // Enhanced JavaScript functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-hide alerts after 5 seconds
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 300);
                }, 5000);
            });
            
            // Enhanced confirmation for dangerous actions
            const dangerousForms = document.querySelectorAll('form[onsubmit]');
            dangerousForms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const message = this.getAttribute('data-confirm') || 
                                   'Are you sure you want to proceed? This action cannot be undone.';
                    if (!confirm(message)) {
                        e.preventDefault();
                    }
                });
            });
            
            // Auto-refresh dashboard every 30 seconds
            <?php if ($active_tab == 'dashboard'): ?>
            setInterval(() => {
                // Only refresh if user is active (mouse movement or keypress)
                if (document.hasFocus()) {
                    window.location.reload();
                }
            }, 30000);
            <?php endif; ?>
            
            // Session timeout warning
            <?php if (isset($session_warning)): ?>
            setTimeout(() => {
                const warning = document.createElement('div');
                warning.className = 'alert alert-warning';
                warning.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Your session will expire in 1 minute. Please save your work.';
                document.querySelector('.admin-container').insertBefore(warning, document.querySelector('.alert:last-child'));
            }, 3540000); // 59 minutes
            <?php endif; ?>
            
            // Enhanced search with debouncing
            let searchTimeout;
            const searchInput = document.querySelector('input[name="search"]');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(() => {
                        if (this.value.length >= 2 || this.value.length === 0) {
                            this.form.submit();
                        }
                    }, 500);
                });
            }
            
            // Toggle advanced options
            const toggleButtons = document.querySelectorAll('[data-toggle]');
            toggleButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const target = document.getElementById(this.getAttribute('data-toggle'));
                    if (target) {
                        target.style.display = target.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });
            
            // Copy to clipboard functionality
            const copyButtons = document.querySelectorAll('[data-copy]');
            copyButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const textToCopy = this.getAttribute('data-copy');
                    navigator.clipboard.writeText(textToCopy).then(() => {
                        const originalText = this.innerHTML;
                        this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                        setTimeout(() => {
                            this.innerHTML = originalText;
                        }, 2000);
                    });
                });
            });
        });
        
        // Enhanced error handling for AJAX requests (if added in future)
        window.addEventListener('error', function(e) {
            console.error('JavaScript Error:', e.error);
        });
    </script>
        <script>
        // Enhanced JavaScript for Audit Log functionality
        
        // Initialize event listeners when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {
            // View log details
            document.querySelectorAll('.view-log-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const logData = this.getAttribute('data-log-data');
                    showLogDetails(logData);
                });
            });
            
            // Copy log data
            document.querySelectorAll('.copy-log-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const logData = this.getAttribute('data-log-data');
                    copyLogToClipboard(logData, this);
                });
            });
            
            // Real-time activity monitor
            initializeActivityMonitor();
            
            // Auto-apply date filters
            initializeDateFilters();
        });
        
        // Enhanced log details display
        function showLogDetails(logData) {
            try {
                const log = JSON.parse(logData);
                const modal = document.getElementById('log-details-modal');
                const content = document.getElementById('log-details-content');
                
                // Determine badge color based on action type
                let badgeClass = 'badge-info';
                let badgeIcon = 'fas fa-info-circle';
                
                if (log.action.includes('failed') || log.action.includes('error')) {
                    badgeClass = 'badge-danger';
                    badgeIcon = 'fas fa-exclamation-triangle';
                } else if (log.action.includes('success') || log.action.includes('created')) {
                    badgeClass = 'badge-success';
                    badgeIcon = 'fas fa-check-circle';
                } else if (log.action.includes('warning')) {
                    badgeClass = 'badge-warning';
                    badgeIcon = 'fas fa-exclamation-circle';
                } else if (log.action.includes('login')) {
                    badgeClass = 'badge-primary';
                    badgeIcon = 'fas fa-sign-in-alt';
                } else if (log.action.includes('delete')) {
                    badgeClass = 'badge-danger';
                    badgeIcon = 'fas fa-trash';
                }
                
                content.innerHTML = `
                    <div class="grid-3" style="margin-bottom: 1.5rem;">
                        <div class="detail-item">
                            <label>Timestamp</label>
                            <div class="detail-value">
                                <i class="fas fa-calendar"></i>
                                ${new Date(log.created_at).toLocaleDateString()}
                            </div>
                            <div class="detail-subvalue">
                                ${new Date(log.created_at).toLocaleTimeString()}
                            </div>
                        </div>
                        <div class="detail-item">
                            <label>Admin User</label>
                            <div class="detail-value">
                                <i class="fas fa-user"></i>
                                ${log.admin_username}
                            </div>
                        </div>
                        <div class="detail-item">
                            <label>Action</label>
                            <div class="detail-value">
                                <span class="badge ${badgeClass}">
                                    <i class="${badgeIcon}"></i> ${log.action}
                                </span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="grid-2" style="margin-bottom: 1.5rem;">
                        <div class="detail-item">
                            <label>IP Address</label>
                            <div class="detail-value">
                                <i class="fas fa-network-wired"></i>
                                <code>${log.ip_address}</code>
                                <button type="button" class="btn btn-sm" onclick="lookupIP('${log.ip_address}')" 
                                        style="padding: 0.1rem 0.3rem; margin-left: 0.5rem;">
                                    <i class="fas fa-search"></i> Lookup
                                </button>
                            </div>
                        </div>
                        <div class="detail-item">
                            <label>User Agent</label>
                            <div class="detail-value">
                                <i class="fas fa-desktop"></i>
                                ${parseUserAgent(log.user_agent)}
                            </div>
                        </div>
                    </div>
                    
                    <div class="detail-item">
                        <label>Details</label>
                        <div class="detail-content" style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: var(--radius); margin-top: 0.5rem; font-family: 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto;">
                            ${log.details || '<em style="color: var(--text-muted);">No details provided</em>'}
                        </div>
                    </div>
                    
                    ${log.user_agent ? `
                    <div class="detail-item" style="margin-top: 1.5rem;">
                        <label>Full User Agent</label>
                        <div class="detail-content" style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: var(--radius); margin-top: 0.5rem; font-size: 0.8rem; word-break: break-all;">
                            ${log.user_agent}
                        </div>
                    </div>
                    ` : ''}
                `;
                
                modal.style.display = 'flex';
                
            } catch (error) {
                console.error('Error displaying log details:', error);
                alert('Error displaying log details: ' + error.message);
            }
        }
        
        // Parse user agent for better display
        function parseUserAgent(userAgent) {
            if (!userAgent || userAgent === 'N/A') return 'Unknown';
            
            let parsed = 'Unknown Browser';
            
            // Simple user agent parsing
            if (userAgent.includes('Chrome')) parsed = 'Chrome';
            else if (userAgent.includes('Firefox')) parsed = 'Firefox';
            else if (userAgent.includes('Safari')) parsed = 'Safari';
            else if (userAgent.includes('Edge')) parsed = 'Edge';
            else if (userAgent.includes('Opera')) parsed = 'Opera';
            
            // Detect OS
            if (userAgent.includes('Windows')) parsed += ' on Windows';
            else if (userAgent.includes('Mac')) parsed += ' on macOS';
            else if (userAgent.includes('Linux')) parsed += ' on Linux';
            else if (userAgent.includes('Android')) parsed += ' on Android';
            else if (userAgent.includes('iOS')) parsed += ' on iOS';
            
            return parsed;
        }
        
        // Copy log to clipboard
        function copyLogToClipboard(logData, button) {
            try {
                const log = JSON.parse(logData);
                const logText = `
AUDIT LOG ENTRY
================
Timestamp: ${new Date(log.created_at).toLocaleString()}
Admin: ${log.admin_username}
Action: ${log.action}
IP Address: ${log.ip_address}
User Agent: ${log.user_agent || 'N/A'}
Details: ${log.details || 'N/A'}
                `.trim();
                
                navigator.clipboard.writeText(logText).then(() => {
                    // Show success feedback
                    const originalHTML = button.innerHTML;
                    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    button.classList.remove('btn-secondary');
                    button.classList.add('btn-success');
                    
                    setTimeout(() => {
                        button.innerHTML = originalHTML;
                        button.classList.remove('btn-success');
                        button.classList.add('btn-secondary');
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy:', err);
                    alert('Failed to copy log data to clipboard');
                });
                
            } catch (error) {
                console.error('Error copying log:', error);
                alert('Error copying log data: ' + error.message);
            }
        }
        
        // IP lookup
        function lookupIP(ip) {
            if (ip && ip !== 'Unknown') {
                window.open(`https://whatismyipaddress.com/ip/${ip}`, '_blank');
            } else {
                alert('No IP address available for lookup');
            }
        }
        
        // Print log details
        function printLogDetails() {
            const content = document.getElementById('log-details-content').innerHTML;
            const printWindow = window.open('', '_blank');
            printWindow.document.write(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Audit Log Entry Details</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
                        .detail-item { margin-bottom: 15px; }
                        label { font-weight: bold; display: block; margin-bottom: 5px; }
                        .detail-value { padding: 8px; background: #f5f5f5; border-radius: 4px; }
                        .detail-content { padding: 10px; background: #f9f9f9; border: 1px solid #ddd; border-radius: 4px; margin-top: 5px; }
                        code { background: #eee; padding: 2px 4px; border-radius: 3px; }
                        .badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; color: white; }
                        .badge-success { background: #28a745; }
                        .badge-danger { background: #dc3545; }
                        .badge-warning { background: #ffc107; color: black; }
                        .badge-info { background: #17a2b8; }
                        .badge-primary { background: #007bff; }
                        @media print {
                            body { margin: 0; }
                            .no-print { display: none; }
                        }
                    </style>
                </head>
                <body>
                    <h1>Audit Log Entry Details</h1>
                    <div>Printed on: ${new Date().toLocaleString()}</div>
                    <hr>
                    ${content}
                    <div class="no-print" style="margin-top: 20px; font-style: italic;">
                        This document was generated from Galaxy Chat Admin Portal
                    </div>
                </body>
                </html>
            `);
            printWindow.document.close();
            printWindow.focus();
            setTimeout(() => {
                printWindow.print();
            }, 500);
        }
        
        // Initialize activity monitor
        function initializeActivityMonitor() {
            const startBtn = document.getElementById('start-monitor');
            const stopBtn = document.getElementById('stop-monitor');
            const feed = document.getElementById('activity-feed');
            let monitorInterval;
            
            if (startBtn) {
                startBtn.addEventListener('click', function() {
                    this.style.display = 'none';
                    stopBtn.style.display = 'inline-block';
                    
                    feed.innerHTML = '<div style="text-align: center; color: var(--success); padding: 1rem;"><i class="fas fa-circle" style="color: var(--success); margin-right: 0.5rem;"></i> Real-time monitoring started...</div>';
                    
                    // Simulate real-time updates (in real implementation, this would use WebSockets)
                    monitorInterval = setInterval(() => {
                        const now = new Date();
                        const timeString = now.toLocaleTimeString();
                        
                        // Sample activities for simulation
                        const activities = [
                            `User login from ${getRandomIP()}`,
                            `Room "General Chat" created`,
                            `User account deleted: spam_user_${Math.floor(Math.random() * 1000)}`,
                            `Data export completed`,
                            `System settings updated`,
                            `Audit log cleared`,
                            `New admin user created`,
                            `Password reset for user`
                        ];
                        
                        const randomActivity = activities[Math.floor(Math.random() * activities.length)];
                        const admins = ['admin', 'superuser', 'moderator', 'system'];
                        const randomAdmin = admins[Math.floor(Math.random() * admins.length)];
                        
                        const activityItem = document.createElement('div');
                        activityItem.style.padding = '0.75rem';
                        activityItem.style.borderBottom = '1px solid var(--border-light)';
                        activityItem.style.fontSize = '0.8rem';
                        activityItem.style.display = 'flex';
                        activityItem.style.alignItems = 'center';
                        activityItem.style.gap = '0.5rem';
                        activityItem.innerHTML = `
                            <i class="fas fa-circle" style="color: var(--success); font-size: 0.5rem;"></i>
                            <span style="flex: 1;">
                                <strong>${randomAdmin}</strong>: ${randomActivity}
                            </span>
                            <span style="color: var(--text-muted); font-size: 0.7rem;">${timeString}</span>
                        `;
                        
                        feed.insertBefore(activityItem, feed.firstChild);
                        
                        // Keep only last 15 items
                        while (feed.children.length > 15) {
                            feed.removeChild(feed.lastChild);
                        }
                    }, 3000);
                });
            }
            
            if (stopBtn) {
                stopBtn.addEventListener('click', function() {
                    this.style.display = 'none';
                    startBtn.style.display = 'inline-block';
                    clearInterval(monitorInterval);
                    
                    feed.innerHTML = '<div style="text-align: center; color: var(--text-muted); font-style: italic; padding: 1rem;">Real-time monitoring stopped.</div>';
                });
            }
        }
        
        // Helper function for random IP generation
        function getRandomIP() {
            return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        }
        
        // Initialize date filters
        function initializeDateFilters() {
            const dateFrom = document.getElementById('date_from');
            const dateTo = document.getElementById('date_to');
            
            if (dateFrom && dateTo) {
                // Set max date for "to" field based on "from" field
                dateFrom.addEventListener('change', function() {
                    dateTo.min = this.value;
                });
                
                // Set min date for "from" field based on "to" field
                dateTo.addEventListener('change', function() {
                    dateFrom.max = this.value;
                });
            }
        }
        
        // Show audit settings
        function showAuditSettings() {
            document.getElementById('audit-settings-modal').style.display = 'flex';
        }
        
        // Modal close function
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        // Close modals when clicking outside
        window.addEventListener('click', function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        });
        
        // Add CSS for detail items
        const style = document.createElement('style');
        style.textContent = `
            .detail-item {
                margin-bottom: 1rem;
            }
            .detail-item label {
                font-weight: 600;
                color: var(--primary);
                margin-bottom: 0.5rem;
                display: block;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            .detail-value {
                padding: 0.75rem;
                background: rgba(255,255,255,0.05);
                border-radius: var(--radius);
                border-left: 3px solid var(--primary);
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            .detail-subvalue {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-top: 0.25rem;
                padding-left: 1.75rem;
            }
            .detail-content {
                background: rgba(255,255,255,0.05);
                padding: 1rem;
                border-radius: var(--radius);
                margin-top: 0.5rem;
                font-family: 'Courier New', monospace;
                white-space: pre-wrap;
                word-break: break-all;
                max-height: 300px;
                overflow-y: auto;
                border: 1px solid var(--border-light);
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>