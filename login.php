<?php
session_start();
include("connection.php");

// Redirect if already logged in
if (isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}

// Helper function to show alert and redirect
function showAlertAndRedirect($message, $redirect = 'login.php') {
    $escapedMessage = json_encode($message);
    echo "<script>alert($escapedMessage); window.location = '$redirect';</script>";
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // Validate inputs
    if (empty($username) || empty($password)) {
        showAlertAndRedirect("Username and password are required.");
    }

    // Use prepared statement to prevent SQL injection
    $query = "SELECT username, password_hash FROM users WHERE username = ? OR email = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $username, $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) == 0) {
        showAlertAndRedirect("Invalid username or password.");
    }

    $user = mysqli_fetch_assoc($result);

    // Verify password
    if (!password_verify($password, $user['password_hash'])) {
        showAlertAndRedirect("Invalid username or password.");
    }

    // Login successful
    $_SESSION['username'] = $user['username'];

    // Update online status
    $query = "UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $user['username']);
    mysqli_stmt_execute($stmt);

    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Galaxy Chat</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: radial-gradient(ellipse at bottom, #1B2735 0%, #090A0F 100%);
            font-family: 'Montserrat', sans-serif;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }

        .login-container {
            background: rgba(13, 13, 39, 0.85);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2.5rem;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            text-align: center;
        }

        .login-container h1 {
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        .login-container p {
            margin-bottom: 2rem;
            color: rgba(255, 255, 255, 0.7);
            font-size: 0.9rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9rem;
        }

        .form-group input {
            width: 100%;
            padding: 0.8rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            color: white;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: rgba(0, 212, 255, 0.5);
            background: rgba(255, 255, 255, 0.15);
        }

        .form-group input::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }

        .login-btn {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.8), rgba(9, 9, 121, 0.8));
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 1rem;
        }

        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 212, 255, 0.3);
        }

        .back-link {
            display: inline-block;
            color: rgba(0, 212, 255, 0.8);
            text-decoration: none;
            font-size: 0.9rem;
            transition: color 0.3s ease;
        }

        .back-link:hover {
            color: rgba(0, 212, 255, 1);
        }

        .error-message {
            background: rgba(255, 107, 107, 0.2);
            border: 1px solid rgba(255, 107, 107, 0.3);
            color: #ff6b6b;
            padding: 0.8rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }

        /* Responsive design */
        @media (max-width: 480px) {
            .login-container {
                padding: 1.5rem;
                margin: 10px;
                max-width: none;
            }

            .login-container h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Welcome Back</h1>
        <p>Sign in to your Galaxy Chat account</p>

        <?php if (isset($_GET['error'])): ?>
            <div class="error-message">
                <?php
                $errors = [
                    'invalid' => 'Invalid username or password',
                    'session' => 'Please login to continue'
                ];
                echo $errors[$_GET['error']] ?? 'Login error occurred';
                ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php">
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required
                       placeholder="Enter your username or email">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required
                       placeholder="Enter your password">
            </div>

            <button type="submit" class="login-btn">Sign In</button>
        </form>

        <a href="welcome.php" class="back-link">← Back to Home</a>
    </div>
</body>
</html>