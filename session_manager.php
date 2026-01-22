<?php
// Enhanced session management with security improvements
session_start();

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Session security settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 3600); // 1 hour
ini_set('session.cookie_lifetime', 0); // Session cookie

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Generate session fingerprint for additional security
if (!isset($_SESSION['fingerprint'])) {
    $_SESSION['fingerprint'] = generateFingerprint();
}

// Validate user session with enhanced security
function validateSession() {
    if (!isset($_SESSION['username'])) {
        header('Location: welcome.php');
        exit();
    }

    // Check session fingerprint
    if (!isset($_SESSION['fingerprint']) || $_SESSION['fingerprint'] !== generateFingerprint()) {
        session_destroy();
        header('Location: welcome.php?error=session_invalid');
        exit();
    }

    // Check if session has expired (24 hours)
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 86400)) {
        session_destroy();
        header('Location: welcome.php?error=session_expired');
        exit();
    }

    // Update last activity
    $_SESSION['last_activity'] = time();
}

// Regenerate session ID to prevent fixation
function regenerateSession() {
    if (!isset($_SESSION['can_regenerate']) || $_SESSION['can_regenerate'] === true) {
        session_regenerate_id(true);
        $_SESSION['can_regenerate'] = false;
        $_SESSION['fingerprint'] = generateFingerprint(); // Update fingerprint after regeneration
    }
}

// Generate session fingerprint based on user agent and IP
function generateFingerprint() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return hash('sha256', $user_agent . $ip . session_id());
}

// Validate CSRF token
function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
}

// Generate secure random token
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// Sanitize input data
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Validate and sanitize file uploads
function validateFileUpload($file, $allowed_types = [], $max_size = 5242880) { // 5MB default
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['valid' => false, 'error' => 'No file uploaded or upload error'];
    }

    if ($file['size'] > $max_size) {
        return ['valid' => false, 'error' => 'File size exceeds limit'];
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if (!empty($allowed_types) && !in_array($mime_type, $allowed_types)) {
        return ['valid' => false, 'error' => 'File type not allowed'];
    }

    return ['valid' => true, 'mime_type' => $mime_type];
}

// Rate limiting helper
$rate_limit_file = __DIR__ . '/rate_limit.json';
function checkRateLimit($identifier, $max_attempts = 5, $time_window = 300) { // 5 attempts per 5 minutes
    global $rate_limit_file;

    if (!file_exists($rate_limit_file)) {
        file_put_contents($rate_limit_file, json_encode([]));
    }

    $data = json_decode(file_get_contents($rate_limit_file), true);
    $now = time();

    // Clean old entries
    foreach ($data as $key => $attempt) {
        if ($now - $attempt['time'] > $time_window) {
            unset($data[$key]);
        }
    }

    // Check current identifier
    if (isset($data[$identifier]) && $data[$identifier]['count'] >= $max_attempts) {
        return false;
    }

    // Add/update attempt
    if (!isset($data[$identifier])) {
        $data[$identifier] = ['count' => 1, 'time' => $now];
    } else {
        $data[$identifier]['count']++;
        $data[$identifier]['time'] = $now;
    }

    file_put_contents($rate_limit_file, json_encode($data));
    return true;
}

// Enhanced logout function
function secureLogout() {
    // Clear session data
    $_SESSION = array();

    // Get session parameters
    $params = session_get_cookie_params();

    // Delete session cookie
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']
    );

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
}
?>