<?php
session_start();
if (isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Galaxy Chat</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
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
        
        .welcome-container {
            background: rgba(13, 13, 39, 0.85);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2.5rem;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        
        .welcome-container h1 {
            margin-bottom: 2rem;
        }
        
        .auth-buttons {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .auth-btn {
            padding: 1rem;
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.8), rgba(9, 9, 121, 0.8));
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
        }
        
        .auth-btn.secondary {
            background: rgba(0, 212, 255, 0.1);
        }
    
        /* ===== COMPREHENSIVE RESPONSIVE DESIGN ===== */
    
        /* ===== MOBILE PHONES (320px - 480px) ===== */
        @media (max-width: 480px) {
            body {
                padding: 10px;
            }
    
            .welcome-container {
                padding: 1.5rem;
                border-radius: 12px;
                margin: 0;
                max-width: 100%;
            }
    
            .welcome-container h1 {
                font-size: 1.8rem;
                margin-bottom: 1rem;
            }
    
            .welcome-container p {
                font-size: 0.9rem;
                margin-bottom: 1.5rem;
            }
    
            .auth-buttons {
                gap: 0.8rem;
            }
    
            .auth-btn {
                padding: 0.9rem;
                font-size: 0.9rem;
                border-radius: 6px;
            }
        }
    
        /* ===== SMALL TABLETS (481px - 768px) ===== */
        @media (min-width: 481px) and (max-width: 768px) {
            .welcome-container {
                padding: 2rem;
                max-width: 380px;
            }
    
            .welcome-container h1 {
                font-size: 2rem;
                margin-bottom: 1.2rem;
            }
    
            .welcome-container p {
                font-size: 0.95rem;
                margin-bottom: 1.8rem;
            }
    
            .auth-btn {
                padding: 1rem;
                font-size: 0.95rem;
            }
        }
    
        /* ===== TABLETS & SMALL LAPTOPS (769px - 1024px) ===== */
        @media (min-width: 769px) and (max-width: 1024px) {
            .welcome-container {
                padding: 2.5rem;
                max-width: 420px;
            }
    
            .welcome-container h1 {
                font-size: 2.2rem;
                margin-bottom: 1.4rem;
            }
    
            .welcome-container p {
                font-size: 1rem;
                margin-bottom: 2rem;
            }
    
            .auth-btn {
                padding: 1.1rem;
                font-size: 1rem;
            }
        }
    
        /* ===== DESKTOPS (1025px - 1440px) ===== */
        @media (min-width: 1025px) and (max-width: 1440px) {
            .welcome-container {
                padding: 3rem;
                max-width: 450px;
            }
    
            .welcome-container h1 {
                font-size: 2.4rem;
                margin-bottom: 1.6rem;
            }
    
            .welcome-container p {
                font-size: 1.05rem;
                margin-bottom: 2.2rem;
            }
    
            .auth-btn {
                padding: 1.2rem;
                font-size: 1.05rem;
            }
        }
    
        /* ===== LARGE SCREENS (1441px+) ===== */
        @media (min-width: 1441px) {
            body {
                background-size: cover;
                background-attachment: fixed;
            }
    
            .welcome-container {
                padding: 3.5rem;
                max-width: 480px;
                backdrop-filter: blur(15px);
            }
    
            .welcome-container h1 {
                font-size: 2.6rem;
                margin-bottom: 1.8rem;
            }
    
            .welcome-container p {
                font-size: 1.1rem;
                margin-bottom: 2.5rem;
            }
    
            .auth-btn {
                padding: 1.3rem;
                font-size: 1.1rem;
            }
        }
    
        /* ===== ORIENTATION CHANGES ===== */
        @media (max-height: 600px) and (orientation: landscape) {
            .welcome-container {
                padding: 1.2rem;
                margin: 5px auto;
            }
    
            .welcome-container h1 {
                font-size: 1.6rem;
                margin-bottom: 0.8rem;
            }
    
            .welcome-container p {
                font-size: 0.85rem;
                margin-bottom: 1.2rem;
            }
    
            .auth-buttons {
                gap: 0.6rem;
            }
    
            .auth-btn {
                padding: 0.8rem;
                font-size: 0.85rem;
            }
        }
    
        /* ===== HIGH DPI SCREENS ===== */
        @media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
            .welcome-container,
            .auth-btn {
                image-rendering: -webkit-optimize-contrast;
                image-rendering: crisp-edges;
            }
    
            .welcome-container h1,
            .welcome-container p,
            .auth-btn {
                font-smoothing: antialiased;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
        }

        .admin-link {
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(255,255,255,0.1);
        }

        .admin-link a:hover {
            color: rgba(0, 212, 255, 0.8);
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="welcome-container">
        <h1>Welcome to Galaxy Chat</h1>
        <p>Connect with others in real-time across the universe</p>
        
        <div class="auth-buttons">
            <a href="signup.php" class="auth-btn">Create Account</a>
            <a href="login.php" class="auth-btn secondary">Login</a>
        </div>

        <div class="admin-link">
            <a href="admin.php" style="color: rgba(255,255,255,0.6); text-decoration: none; font-size: 0.9rem;">🔧 Admin Portal</a>
        </div>
    </div>
</body>
</html>