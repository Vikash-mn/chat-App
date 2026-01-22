<?php
session_start();
include("connection.php");

// Redirect if already logged in
if (isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}

// Helper function to show alert and redirect
function showAlertAndRedirect($message, $redirect = 'signup.php') {
    $escapedMessage = json_encode($message);
    echo "<script>alert($escapedMessage); window.location = '$redirect';</script>";
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Validate inputs
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        showAlertAndRedirect("All fields are required.");
    }

    // Validate username
    if (strlen($username) < 3 || strlen($username) > 50) {
        showAlertAndRedirect("Username must be between 3-50 characters.");
    }

    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        showAlertAndRedirect("Username can only contain letters, numbers, and underscores.");
    }
    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        showAlertAndRedirect("Please enter a valid email address.");
    }

    // Validate password
    if (strlen($password) < 6) {
        showAlertAndRedirect("Password must be at least 6 characters long.");
    }

    if ($password !== $confirm_password) {
        showAlertAndRedirect("Passwords do not match.");
    }

    // Check if username or email already exists
    $query = "SELECT username FROM users WHERE username = ? OR email = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $username, $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) > 0) {
        showAlertAndRedirect("Username or email already exists. Please choose different ones.");
    }
    mysqli_stmt_close($stmt);

    // Hash password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user
    $query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "sss", $username, $email, $password_hash);

    if (mysqli_stmt_execute($stmt)) {
        // Set session variables
        $_SESSION['username'] = $username;

        // Update online status
        $query = "UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP WHERE username = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);

        header("Location: index.php");
        exit();
    } else {
        showAlertAndRedirect("Error creating account. Please try again.");
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - Galaxy Chat</title>
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

        .signup-container {
            background: rgba(13, 13, 39, 0.85);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2.5rem;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            text-align: center;
        }

        .signup-container h1 {
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        .signup-container p {
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

        .signup-btn {
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

        .signup-btn:hover {
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

        /* Password strength indicator */
        .password-strength {
            margin-top: 0.5rem;
            font-size: 0.8rem;
        }

        .strength-weak { color: #ff6b6b; }
        .strength-medium { color: #ffa726; }
        .strength-strong { color: #66bb6a; }

        /* Responsive design */
        @media (max-width: 480px) {
            .signup-container {
                padding: 1.5rem;
                margin: 10px;
                max-width: none;
            }

            .signup-container h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="signup-container">
        <h1>Join Galaxy Chat</h1>
        <p>Create your account to start chatting</p>

        <?php if (isset($_GET['error'])): ?>
            <div class="error-message">
                <?php
                $errors = [
                    'exists' => 'Username or email already exists',
                    'password' => 'Passwords do not match',
                    'validation' => 'Please check your input data'
                ];
                echo $errors[$_GET['error']] ?? 'Registration error occurred';
                ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="signup.php" id="signupForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required
                       placeholder="Choose a username" maxlength="50">
            </div>

            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required
                       placeholder="Enter your email">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required
                       placeholder="Create a password" minlength="6">
                <div id="password-strength" class="password-strength" style="display: none;"></div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       placeholder="Confirm your password">
            </div>

            <button type="submit" class="signup-btn">Create Account</button>
        </form>

        <a href="welcome.php" class="back-link">← Back to Home</a>
    </div>

    <script>
        // Password strength checker
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const strengthDiv = document.getElementById('password-strength');

            if (password.length === 0) {
                strengthDiv.style.display = 'none';
                return;
            }

            let strength = 0;
            let feedback = '';

            if (password.length >= 8) strength += 1;
            if (/[a-z]/.test(password)) strength += 1;
            if (/[A-Z]/.test(password)) strength += 1;
            if (/[0-9]/.test(password)) strength += 1;

            switch (strength) {
                case 0:
                case 1:
                    feedback = 'Weak password';
                    strengthDiv.className = 'password-strength strength-weak';
                    break;
                case 2:
                case 3:
                    feedback = 'Medium strength';
                    strengthDiv.className = 'password-strength strength-medium';
                    break;
                case 4:
                    feedback = 'Strong password';
                    strengthDiv.className = 'password-strength strength-strong';
                    break;
            }

            strengthDiv.textContent = feedback;
            strengthDiv.style.display = 'block';
        });

        // Form validation
        document.getElementById('signupForm').addEventListener('submit', function(e) {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;

            if (password !== confirmPassword) {
                e.preventDefault();
                alert('Passwords do not match!');
                return false;
            }

            if (password.length < 6) {
                e.preventDefault();
                alert('Password must be at least 6 characters long!');
                return false;
            }
        });
    </script>
</body>
</html>