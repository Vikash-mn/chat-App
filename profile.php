<?php
session_start();
include("connection.php");

if (!isset($_SESSION['username'])) {
    header("Location: welcome.php");
    exit();
}

$username = $_SESSION['username'];
$message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['profile_photo'])) {
    $target_dir = "uploads/avatars/";
    if (!file_exists($target_dir)) {
        if (!mkdir($target_dir, 0777, true)) {
            $message = 'Failed to create upload directory.';
        }
    }

    if (empty($message)) {
        $file = $_FILES['profile_photo'];

        // Check if file was uploaded successfully
        if ($file['error'] !== UPLOAD_ERR_OK) {
            $message = 'File upload error. Please try again.';
        } else {
            $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
            $max_size = 2 * 1024 * 1024; // 2MB

            if (!in_array($file['type'], $allowed_types)) {
                $message = 'Only JPG, PNG, and GIF files are allowed.';
            } elseif ($file['size'] > $max_size) {
                $message = 'File size must be less than 2MB.';
            } else {
                $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                $filename = $username . '_' . time() . '.' . $extension;
                $target_file = $target_dir . $filename;

                if (move_uploaded_file($file['tmp_name'], $target_file)) {
                    // Update database
                    $query = "UPDATE users SET profile_photo = ? WHERE username = ?";
                    $stmt = mysqli_prepare($conn, $query);
                    if ($stmt) {
                        mysqli_stmt_bind_param($stmt, "ss", $target_file, $username);
                        if (mysqli_stmt_execute($stmt)) {
                            $message = 'Profile photo updated successfully!';
                            // Refresh current photo
                            $current_photo = $target_file;
                        } else {
                            $message = 'Failed to update database.';
                            unlink($target_file); // Delete uploaded file if DB update fails
                        }
                    } else {
                        $message = 'Database error. Please try again.';
                        unlink($target_file);
                    }
                } else {
                    $message = 'Failed to save uploaded file.';
                }
            }
        }
    }
}

// Get current profile photo
$current_photo = null;
$query = "SELECT profile_photo FROM users WHERE username = ?";
$stmt = mysqli_prepare($conn, $query);
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $username);
    if (mysqli_stmt_execute($stmt)) {
        $result = mysqli_stmt_get_result($stmt);
        if ($result && mysqli_num_rows($result) > 0) {
            $user = mysqli_fetch_assoc($result);
            $current_photo = $user['profile_photo'];
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Galaxy Chat</title>
    <style>
        body {
            background: radial-gradient(ellipse at bottom, #1B2735 0%, #090A0F 100%);
            color: white;
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        .profile-container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(20, 20, 50, 0.7);
            border-radius: 15px;
            padding: 2rem;
            backdrop-filter: blur(10px);
        }
        .profile-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .current-photo {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: linear-gradient(135deg, #00d4ff, #090979);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3rem;
            margin: 0 auto 1rem;
            overflow: hidden;
        }
        .current-photo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .upload-form {
            background: rgba(0, 0, 0, 0.2);
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .file-input {
            display: block;
            margin: 1rem 0;
            padding: 0.5rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 5px;
            color: white;
            width: 100%;
        }
        .upload-btn {
            background: linear-gradient(135deg, #00d4ff, #0077ff);
            border: none;
            padding: 0.8rem 1.5rem;
            border-radius: 5px;
            color: white;
            cursor: pointer;
            font-size: 1rem;
        }
        .upload-btn:hover {
            transform: translateY(-2px);
        }
        .message {
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            text-align: center;
        }
        .success { background: rgba(0, 255, 0, 0.2); color: #4CAF50; }
        .error { background: rgba(255, 0, 0, 0.2); color: #f44336; }
        .back-btn {
            display: inline-block;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            padding: 0.8rem 1.5rem;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 1rem;
            transition: all 0.3s ease;
        }
        .back-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body>
    <div class="profile-container">
        <div class="profile-header">
            <h1><?php echo htmlspecialchars($username); ?>'s Profile</h1>
        </div>

        <div class="current-photo">
            <?php if ($current_photo && file_exists($current_photo)): ?>
                <img src="<?php echo htmlspecialchars($current_photo); ?>" alt="Profile Photo">
            <?php else: ?>
                <?php echo strtoupper(substr($username, 0, 1)); ?>
            <?php endif; ?>
        </div>

        <?php if ($message): ?>
            <div class="message <?php echo strpos($message, 'success') !== false ? 'success' : 'error'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data" class="upload-form">
            <h3>Update Profile Photo</h3>
            <p style="font-size: 0.9rem; color: rgba(255,255,255,0.7); margin-bottom: 1rem;">
                Upload a JPG, PNG, or GIF image (max 2MB)
            </p>
            <input type="file" name="profile_photo" accept="image/*" class="file-input" required>
            <button type="submit" class="upload-btn">Upload Photo</button>
        </form>

        <div style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
            <h4 style="margin: 0 0 0.5rem 0; color: #00d4ff;">Database Status</h4>
            <p style="font-size: 0.9rem; margin: 0; color: rgba(255,255,255,0.8);">
                <?php
                $check_query = "SHOW COLUMNS FROM users LIKE 'profile_photo'";
                $check_result = mysqli_query($conn, $check_query);
                if (mysqli_num_rows($check_result) > 0) {
                    echo "✅ Database is ready for profile photos!";
                } else {
                    echo "⚠️ Database migration needed. Please run the SQL commands provided earlier.";
                }
                ?>
            </p>
        </div>

        <div style="text-align: center;">
            <a href="index.php" class="back-btn">← Back to Chat</a>
        </div>
    </div>
</body>
</html>