<?php
declare(strict_types=1);

/**
 * Galaxy Chat - Advanced Chat Room System
 * Enterprise-grade real-time chat application with advanced security and features
 * 
 * @package GalaxyChat
 * @version 2.0.0
 * @license MIT
 */

// Start session with secure configuration
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 86400, // 24 hours
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? 'localhost',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
}

// Regenerate session ID periodically for security
if (!isset($_SESSION['last_regeneration']) || time() - $_SESSION['last_regeneration'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
}

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://ajax.googleapis.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'");

// Include database connection with comprehensive error handling
if (!file_exists(__DIR__ . '/connection.php')) {
    error_log("Database connection file not found");
    http_response_code(500);
    exit('<h1>System Maintenance</h1><p>Please try again later.</p>');
}

require_once __DIR__ . '/connection.php';

// Verify database connection
if (!$conn || $conn->connect_error) {
    error_log("Database connection failed: " . ($conn->connect_error ?? 'Unknown error'));
    http_response_code(503);
    exit('<h1>Service Temporarily Unavailable</h1><p>Our chat service is currently undergoing maintenance. Please check back shortly.</p>');
}

/**
 * Comprehensive Input Validation Class
 * Provides robust validation and sanitization for all user inputs
 */
class InputValidator {
    private array $errors = [];
    private array $validation_rules = [];
    
    public function __construct() {
        $this->validation_rules = [
            'roomname' => [
                'required' => true,
                'max_length' => 50,
                'pattern' => '/^[a-zA-Z0-9_\- ]+$/',
                'error_messages' => [
                    'required' => 'Room name is required',
                    'max_length' => 'Room name must be less than 50 characters',
                    'pattern' => 'Room name can only contain letters, numbers, spaces, hyphens and underscores'
                ]
            ],
            'message' => [
                'required' => true,
                'max_length' => 1000,
                'pattern' => '/^(?!.*<script)(?!.*javascript:)(?!.*onload=)(?!.*onerror=).*$/i',
                'error_messages' => [
                    'required' => 'Message cannot be empty',
                    'max_length' => 'Message must be less than 1000 characters',
                    'pattern' => 'Message contains potentially dangerous content'
                ]
            ],
            'username' => [
                'required' => true,
                'max_length' => 30,
                'pattern' => '/^[a-zA-Z0-9_\-]+$/',
                'error_messages' => [
                    'required' => 'Username is required',
                    'max_length' => 'Username must be less than 30 characters',
                    'pattern' => 'Username can only contain letters, numbers, hyphens and underscores'
                ]
            ]
        ];
    }
    
    public function validate(string $field, string $value): bool {
        $this->errors = [];
        
        if (!isset($this->validation_rules[$field])) {
            $this->errors[] = "Unknown validation field: {$field}";
            return false;
        }
        
        $rules = $this->validation_rules[$field];
        $value = trim($value);
        
        // Required validation
        if ($rules['required'] && empty($value)) {
            $this->errors[] = $rules['error_messages']['required'];
            return false;
        }
        
        // Skip further validation if value is empty and not required
        if (empty($value) && !$rules['required']) {
            return true;
        }
        
        // Max length validation
        if (isset($rules['max_length']) && strlen($value) > $rules['max_length']) {
            $this->errors[] = $rules['error_messages']['max_length'];
            return false;
        }
        
        // Pattern validation
        if (isset($rules['pattern']) && !preg_match($rules['pattern'], $value)) {
            $this->errors[] = $rules['error_messages']['pattern'];
            return false;
        }
        
        return true;
    }
    
    public function validateRoomName(string $roomname): bool {
        return $this->validate('roomname', $roomname);
    }
    
    public function validateMessage(string $message): bool {
        return $this->validate('message', $message);
    }
    
    public function validateUsername(string $username): bool {
        return $this->validate('username', $username);
    }
    
    public function validateCSRFToken(string $token): bool {
        if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            $this->errors[] = "CSRF token validation failed";
            return false;
        }
        return true;
    }
    
    public function getErrors(): array {
        return $this->errors;
    }
    
    public function getFirstError(): string {
        return $this->errors[0] ?? 'Unknown error';
    }
    
    public function clearErrors(): void {
        $this->errors = [];
    }
}

/**
 * Advanced Security Service
 * Provides comprehensive security features including encryption, sanitization, and threat detection
 */
class SecurityService {
    private string $encryption_key;
    private array $threat_patterns = [
        '/<script\b[^>]*>(.*?)<\/script>/is',
        '/javascript:\s*[^"\' ]*/i',
        '/on\w+\s*=\s*["\'][^"\']*["\']/i',
        '/vbscript:\s*[^"\' ]*/i',
        '/expression\s*\([^)]*\)/i',
        '/url\s*\([^)]*\)/i',
        '/<iframe\b[^>]*>(.*?)<\/iframe>/is',
        '/<object\b[^>]*>(.*?)<\/object>/is',
        '/<embed\b[^>]*>(.*?)<\/embed>/is',
        '/<applet\b[^>]*>(.*?)<\/applet>/is',
        '/<meta\b[^>]*>(.*?)<\/meta>/is',
        '/<link\b[^>]*>(.*?)<\/link>/is'
    ];
    
    public function __construct() {
        // Use environment variable for encryption key, fallback to session
        $this->encryption_key = $_ENV['ENCRYPTION_KEY'] ?? 
                               ($_SESSION['encryption_key'] ?? $this->generateEncryptionKey());
        
        // Store in session if not using environment variables
        if (!isset($_ENV['ENCRYPTION_KEY'])) {
            $_SESSION['encryption_key'] = $this->encryption_key;
        }
    }
    
    private function generateEncryptionKey(): string {
        return bin2hex(random_bytes(32));
    }
    
    public function sanitizeInput(string $input, bool $allow_html = false): string {
        $input = trim($input);
        
        // Remove null bytes
        $input = str_replace("\0", '', $input);
        
        // Normalize line endings
        $input = str_replace(["\r\n", "\r"], "\n", $input);
        
        if ($allow_html) {
            // Allow limited HTML but sanitize it
            $input = strip_tags($input, '<p><br><strong><em><u><s><code><pre>');
            $input = $this->sanitizeHtml($input);
        } else {
            // Convert special characters to HTML entities
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        return $input;
    }
    
    private function sanitizeHtml(string $html): string {
        // Remove any potentially dangerous attributes
        $html = preg_replace('/\son\w+\s*=\s*["\'][^"\']*["\']/i', '', $html);
        $html = preg_replace('/\sstyle\s*=\s*["\'][^"\']*["\']/i', '', $html);
        
        return $html;
    }
    
    public function generateCSRFToken(): string {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        // Regenerate token every 30 minutes for security
        if (time() - $_SESSION['csrf_token_time'] > 1800) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'];
    }
    
    public function validateCSRFToken(string $token, int $max_age = 7200): bool {
        if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
            return false;
        }
        
        // Check token age
        if (time() - $_SESSION['csrf_token_time'] > $max_age) {
            unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    public function rateLimitCheck(string $identifier, int $max_attempts = 10, int $time_window = 3600): bool {
        $key = "rate_limit_{$identifier}";
        
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = [
                'attempts' => 1,
                'first_attempt' => time()
            ];
            return true;
        }
        
        $limit_data = $_SESSION[$key];
        
        // Reset if time window has passed
        if (time() - $limit_data['first_attempt'] > $time_window) {
            $_SESSION[$key] = [
                'attempts' => 1,
                'first_attempt' => time()
            ];
            return true;
        }
        
        // Check if exceeded max attempts
        if ($limit_data['attempts'] >= $max_attempts) {
            return false;
        }
        
        // Increment attempts
        $_SESSION[$key]['attempts']++;
        return true;
    }
}

/**
 * Comprehensive Room Management System
 * Handles all room-related operations with advanced features
 */
class RoomManager {
    private mysqli $conn;
    private SecurityService $security;
    private InputValidator $validator;
    
    public function __construct(mysqli $conn, SecurityService $security, InputValidator $validator) {
        $this->conn = $conn;
        $this->security = $security;
        $this->validator = $validator;
    }
    
    public function roomExists(string $roomname): bool {
        $stmt = $this->conn->prepare("
            SELECT 1 FROM rooms
            WHERE roomname = ? AND deleted_at IS NULL
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare room exists statement: " . $this->conn->error);
            return false;
        }
        
        $stmt->bind_param("s", $roomname);
        $stmt->execute();
        $result = $stmt->get_result();
        $exists = $result->num_rows > 0;
        $stmt->close();
        
        return $exists;
    }
    
    public function getUserAccess(string $roomname, string $user_token): array {
        $stmt = $this->conn->prepare("
            SELECT
                ru.username,
                'user' as role,
                u.email,
                u.profile_photo,
                r.creator,
                r.is_private,
                ru.joined_at,
                ru.last_active
            FROM room_users ru
            JOIN users u ON ru.username = u.username
            JOIN rooms r ON ru.roomname = r.roomname
            WHERE ru.roomname = ?
            AND ru.user_token = ?
            AND ru.removed_at IS NULL
            AND r.deleted_at IS NULL
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare user access statement: " . $this->conn->error);
            return [];
        }
        
        $stmt->bind_param("ss", $roomname, $user_token);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        return $user ?: [];
    }
    
    public function isRoomCreator(string $roomname, string $username): bool {
        $stmt = $this->conn->prepare("\r
            SELECT creator FROM rooms\r
            WHERE roomname = ? AND deleted_at IS NULL\r
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare is room creator statement: " . $this->conn->error);
            return false;
        }
        
        $stmt->bind_param("s", $roomname);
        $stmt->execute();
        $result = $stmt->get_result();
        $room = $result->fetch_assoc();
        $stmt->close();
        
        return $room && $room['creator'] === $username;
    }
    
    // New: check if a user is an admin of the room
    public function isRoomAdmin(string $roomname, string $username): bool {
        $stmt = $this->conn->prepare("\r
            SELECT 1 FROM room_admins
            WHERE roomname = ? AND username = ?
        ");
        if (!$stmt) {
            error_log("Failed to prepare is room admin statement: " . $this->conn->error);
            return false;
        }
        $stmt->bind_param("ss", $roomname, $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $isAdmin = $result->num_rows > 0;
        $stmt->close();
        return $isAdmin;
    }
    
    public function getRoomInfo(string $roomname): array {
        $stmt = $this->conn->prepare("\r
            SELECT\r
                roomname,\r
                creator,\r
                display_photo,\r
                is_private,\r
                created_at,\r
                description,\r
                max_members,\r
                theme,\r
                welcome_message\r
            FROM rooms\r
            WHERE roomname = ? AND deleted_at IS NULL\r
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare room info statement: " . $this->conn->error);
            return [];
        }
        
        $stmt->bind_param("s", $roomname);
        $stmt->execute();
        $result = $stmt->get_result();
        $room = $result->fetch_assoc();
        $stmt->close();
        
        return $room ?: [];
    }

    public function updateUserOnlineStatus(string $username): bool {
        // Update existing user
        $stmt = $this->conn->prepare("
            UPDATE users 
            SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP
            WHERE username = ?
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare update online status statement: " . $this->conn->error);
            return false;
        }
        
        $stmt->bind_param("s", $username);
        $result = $stmt->execute();
        $stmt->close();
        
        return $result;
    }
    
    public function addMessage(string $username, string $message, string $roomname): array {
        // Rate limiting check
        if (!$this->security->rateLimitCheck("message_{$username}", 30, 60)) {
            return ['success' => false, 'error' => 'Rate limit exceeded. Please wait before sending more messages.'];
        }
        
        $filtered_msg = $this->security->sanitizeInput($message);
        
        $stmt = $this->conn->prepare("
            INSERT INTO messages (username, msg, roomname)
            VALUES (?, ?, ?)
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare add message statement: " . $this->conn->error);
            return ['success' => false, 'error' => 'Database error'];
        }
        
        $stmt->bind_param("sss", $username, $filtered_msg, $roomname);
        $result = $stmt->execute();
        $message_id = $stmt->insert_id;
        $stmt->close();
        
        if ($result) {
            return [
                'success' => true,
                'message_id' => $message_id,
                'timestamp' => date('Y-m-d H:i:s')
            ];
        } else {
            return ['success' => false, 'error' => 'Failed to send message'];
        }
    }
    
    public function updateTypingStatus(string $roomname, string $username, bool $is_typing): bool {
        $stmt = $this->conn->prepare("
            INSERT INTO typing_indicators (roomname, username, is_typing) 
            VALUES (?, ?, ?) 
            ON DUPLICATE KEY UPDATE 
                is_typing = ?, 
                last_updated = CURRENT_TIMESTAMP
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare typing status statement: " . $this->conn->error);
            return false;
        }
        
        $typing_int = $is_typing ? 1 : 0;
        $stmt->bind_param("ssii", $roomname, $username, $typing_int, $typing_int);
        $result = $stmt->execute();
        $stmt->close();
        
        return $result;
    }
    
    public function getRoomMembers(string $roomname): array {
        $stmt = $this->conn->prepare("
            SELECT
                u.username,
                'user' as role,
                u.profile_photo,
                u.is_online,
                u.last_seen,
                ru.joined_at,
                ru.last_active,
                CASE
                    WHEN u.last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE) THEN 'online'
                    WHEN u.last_seen > DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 'recent'
                    ELSE 'offline'
                END as status
            FROM room_users ru
            JOIN users u ON ru.username = u.username
            WHERE ru.roomname = ? AND ru.removed_at IS NULL
            ORDER BY
                u.is_online DESC,
                status DESC,
                u.username ASC
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare room members statement: " . $this->conn->error);
            return [];
        }
        
        $stmt->bind_param("s", $roomname);
        $stmt->execute();
        $result = $stmt->get_result();
        $members = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        
        return $members;
    }
    
    public function getPendingRequests(string $roomname): array {
        $stmt = $this->conn->prepare("
            SELECT
                id,
                username,
                requested_at,
                status
            FROM join_requests
            WHERE roomname = ?
            ORDER BY requested_at ASC
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare pending requests statement: " . $this->conn->error);
            return [];
        }
        
        $stmt->bind_param("s", $roomname);
        $stmt->execute();
        $result = $stmt->get_result();
        $requests = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        
        return $requests;
    }
    
    public function inviteMember(string $roomname, string $username, string $invited_by): array {
    // Check if user exists
    $user_check = $this->conn->prepare("SELECT username FROM users WHERE username = ?");
    $user_check->bind_param("s", $username);
    $user_check->execute();
    $user_result = $user_check->get_result();
    
    if ($user_result->num_rows === 0) {
        $user_check->close();
        return ['success' => false, 'error' => 'User not found'];
    }
    $user_check->close();
    
    // Check if already a member
    $member_check = $this->conn->prepare("
        SELECT 1 FROM room_users
        WHERE roomname = ? AND username = ? AND removed_at IS NULL
    ");
    $member_check->bind_param("ss", $roomname, $username);
    $member_check->execute();
    $member_result = $member_check->get_result();
    
    if ($member_result->num_rows > 0) {
        $member_check->close();
        return ['success' => false, 'error' => 'User is already a member of this room'];
    }
    $member_check->close();
    
    // Check for existing pending request
    $request_check = $this->conn->prepare("
        SELECT 1 FROM join_requests 
        WHERE roomname = ? AND username = ? AND status = 'pending'
    ");
    $request_check->bind_param("ss", $roomname, $username);
    $request_check->execute();
    $request_result = $request_check->get_result();
    
    if ($request_result->num_rows > 0) {
        $request_check->close();
        return ['success' => false, 'error' => 'User already has a pending invitation'];
    }
    $request_check->close();
    
    // Create join request
    $stmt = $this->conn->prepare("
        INSERT INTO join_requests (roomname, username, requested_by, status)
        VALUES (?, ?, ?, 'pending')
    ");
    
    if (!$stmt) {
        error_log("Failed to prepare invite member statement: " . $this->conn->error);
        return ['success' => false, 'error' => 'Database error'];
    }
    
    $stmt->bind_param("sss", $roomname, $username, $invited_by);
    $result = $stmt->execute();
    $stmt->close();
    
    if ($result) {
        return ['success' => true, 'message' => 'Invitation sent successfully'];
    } else {
        return ['success' => false, 'error' => 'Failed to send invitation'];
    }
}
    
    public function removeMember(string $roomname, string $username): array {
        // Cannot remove room creator
        $room_info = $this->getRoomInfo($roomname);
        if ($room_info['creator'] === $username) {
            return ['success' => false, 'error' => 'Cannot remove room creator'];
        }
        
        $stmt = $this->conn->prepare("
            UPDATE room_users
            SET removed_at = CURRENT_TIMESTAMP, removed_by = ?
            WHERE roomname = ? AND username = ?
        ");
        
        if (!$stmt) {
            error_log("Failed to prepare remove member statement: " . $this->conn->error);
            return ['success' => false, 'error' => 'Database error'];
        }
        
        $removed_by = $_SESSION['username'] ?? 'system';
        $stmt->bind_param("sss", $removed_by, $roomname, $username);
        $result = $stmt->execute();
        $stmt->close();
        
        if ($result) {
            return ['success' => true, 'message' => 'Member removed successfully'];
        } else {
            return ['success' => false, 'error' => 'Failed to remove member'];
        }
    }
    
    public function getRoomStatistics(string $roomname): array {
        $stats = [];
        
        // Total messages
        $stmt1 = $this->conn->prepare("SELECT COUNT(*) as total_messages FROM messages WHERE roomname = ?");
        $stmt1->bind_param("s", $roomname);
        $stmt1->execute();
        $result1 = $stmt1->get_result();
        $stats['total_messages'] = $result1->fetch_assoc()['total_messages'] ?? 0;
        $stmt1->close();
        
        // Active members
        $stmt2 = $this->conn->prepare("
            SELECT COUNT(*) as active_members
            FROM room_users
            WHERE roomname = ? AND removed_at IS NULL
        ");
        $stmt2->bind_param("s", $roomname);
        $stmt2->execute();
        $result2 = $stmt2->get_result();
        $stats['active_members'] = $result2->fetch_assoc()['active_members'] ?? 0;
        $stmt2->close();
        
        // Online members
        $stmt3 = $this->conn->prepare("
            SELECT COUNT(*) as online_members
            FROM room_users ru
            JOIN users u ON ru.username = u.username
            WHERE ru.roomname = ? AND ru.removed_at IS NULL AND u.is_online = TRUE
        ");
        $stmt3->bind_param("s", $roomname);
        $stmt3->execute();
        $result3 = $stmt3->get_result();
        $stats['online_members'] = $result3->fetch_assoc()['online_members'] ?? 0;
        $stmt3->close();
        
        return $stats;
    }
}

// Custom error handler
set_error_handler(function($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return;
    }
    
    error_log("PHP Error: {$message} in {$file} on line {$line}");
    return true;
});

// Custom exception handler
set_exception_handler(function($exception) {
    error_log("Uncaught exception: " . $exception->getMessage() . " in " . $exception->getFile() . " on line " . $exception->getLine());
    
    http_response_code(500);
    
    if (ini_get('display_errors')) {
        echo "<div style='background: #f8d7da; color: #721c24; padding: 20px; margin: 10px; border: 1px solid #f5c6cb; border-radius: 4px;'>
                <h3>System Error</h3>
                <p><strong>Error:</strong> " . htmlspecialchars($exception->getMessage()) . "</p>
                <p>Please try again later or contact support if the problem persists.</p>
              </div>";
    } else {
        echo "<div style='background: #f8d7da; color: #721c24; padding: 20px; margin: 10px; border: 1px solid #f5c6cb; border-radius: 4px;'>
                <h3>System Temporarily Unavailable</h3>
                <p>We're experiencing technical difficulties. Please try again in a few moments.</p>
              </div>";
    }
    
    exit();
});

// Initialize services
$validator = new InputValidator();
$security = new SecurityService();
$roomManager = new RoomManager($conn, $security, $validator);

// ===== HANDLE POST REQUESTS (API CALLS) FIRST =====
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    try {
        // Validate session for API calls
        if (!isset($_SESSION['username']) || !isset($_SESSION['current_room'])) {
            throw new Exception('Session expired. Please refresh the page.');
        }
        
        if (!isset($_POST['action'])) {
            throw new InvalidArgumentException('No action specified');
        }
        
        $action = $security->sanitizeInput($_POST['action']);
        $roomname = $security->sanitizeInput($_POST['roomname'] ?? $_SESSION['current_room']);
        
        // Validate room access
        $cookie_name = 'user_token_' . $roomname;
        if (!isset($_COOKIE[$cookie_name])) {
            throw new Exception('Room access denied. Please rejoin the room.');
        }
        
        $user_token = $_COOKIE[$cookie_name];
        $user_access = $roomManager->getUserAccess($roomname, $user_token);
        
        if (empty($user_access)) {
            throw new Exception('Invalid user token. Please refresh the page.');
        }
        
        switch ($action) {
            case 'send_message':
                if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF token validation failed');
                }
                
                if (!$validator->validateMessage($_POST['message'] ?? '')) {
                    throw new InvalidArgumentException($validator->getFirstError());
                }
                
                $message = $_POST['message'];
                $result = $roomManager->addMessage($_SESSION['username'], $message, $roomname);
                echo json_encode($result);
                break;
            
            case 'invite_member':
    $isRoomCreator = $roomManager->isRoomCreator($roomname, $_SESSION['username']);
    $isRoomAdmin = $roomManager->isRoomAdmin($roomname, $_SESSION['username']);
    if (!$isRoomCreator && !$isRoomAdmin) {
        throw new RuntimeException('Access denied: Only room creator or admins can invite');
    }
    
    if (!$validator->validateUsername($_POST['username'] ?? '')) {
        throw new InvalidArgumentException($validator->getFirstError());
    }
    
    $username = $security->sanitizeInput($_POST['username']);
    
    // Check if user exists
    $user_check = $conn->prepare("SELECT username FROM users WHERE username = ?");
    $user_check->bind_param("s", $username);
    $user_check->execute();
    $user_result = $user_check->get_result();
    
    if ($user_result->num_rows === 0) {
        $user_check->close();
        throw new Exception('User not found');
    }
    $user_check->close();
    
    // Check if already a member
    $member_check = $conn->prepare("\r
        SELECT 1 FROM room_users \r
        WHERE roomname = ? AND username = ? AND removed_at IS NULL\r
    ");
    $member_check->bind_param("ss", $roomname, $username);
    $member_check->execute();
    $member_result = $member_check->get_result();
    
    if ($member_result->num_rows > 0) {
        $member_check->close();
        throw new Exception('User is already a member of this room');
    }
    $member_check->close();
    
    // Check if already has a pending request
    $request_check = $conn->prepare("\r
        SELECT 1 FROM join_requests \r
        WHERE roomname = ? AND username = ? AND status = 'pending'\r
    ");
    $request_check->bind_param("ss", $roomname, $username);
    $request_check->execute();
    $request_result = $request_check->get_result();
    
    if ($request_result->num_rows > 0) {
        $request_check->close();
        throw new Exception('User already has a pending invitation');
    }
    $request_check->close();
    
    // Create join request
    $stmt = $conn->prepare("\r
        INSERT INTO join_requests (roomname, username, requested_by, status) \r
        VALUES (?, ?, ?, 'pending')\r
    ");
    $stmt->bind_param("sss", $roomname, $username, $_SESSION['username']);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Invitation sent successfully']);
    } else {
        throw new Exception('Failed to send invitation');
    }
    $stmt->close();
    break;

    // Add this to the switch statement in your POST handler in room.php
case 'leave_room':
    if (!isset($_SESSION['username'])) {
        throw new Exception('Not logged in');
    }
    
    // Remove user from room
    $stmt = $conn->prepare("DELETE FROM room_users WHERE roomname = ? AND username = ?");
    $stmt->bind_param("ss", $roomname, $_SESSION['username']);
    
    if ($stmt->execute()) {
        // Clear room cookie
        setcookie('user_token_' . $roomname, '', time() - 3600, '/');
        echo json_encode(['success' => true, 'message' => 'Left room successfully']);
    } else {
        throw new Exception('Failed to leave room');
    }
    $stmt->close();
    break;
            // Add this to your POST handler
case 'join_room':
    if (!isset($_SESSION['username'])) {
        throw new Exception('Not logged in');
    }
    
    // Check if room exists and is public
    $room_check = $conn->prepare("SELECT is_private FROM rooms WHERE roomname = ? AND deleted_at IS NULL");
    $room_check->bind_param("s", $roomname);
    $room_check->execute();
    $room_result = $room_check->get_result();
    $room_data = $room_result->fetch_assoc();
    $room_check->close();
    
    if (!$room_data) {
        throw new Exception('Room not found');
    }
    
    if ($room_data['is_private']) {
        throw new Exception('This is a private room. You need an invitation to join.');
    }
    
    // Check if already a member
    $member_check = $conn->prepare("SELECT 1 FROM room_users WHERE roomname = ? AND username = ? AND removed_at IS NULL");
    $member_check->bind_param("ss", $roomname, $_SESSION['username']);
    $member_check->execute();
    $member_result = $member_check->get_result();
    
    if ($member_result->num_rows > 0) {
        $member_check->close();
        throw new Exception('You are already a member of this room');
    }
    $member_check->close();
    
    // Add user to room
    $user_token = bin2hex(random_bytes(16));
    $stmt = $conn->prepare("INSERT INTO room_users (roomname, username, user_token, joined_at) VALUES (?, ?, ?, NOW())");
    $stmt->bind_param("sss", $roomname, $_SESSION['username'], $user_token);
    
    if ($stmt->execute()) {
        // Set cookie for room access
        setcookie('user_token_' . $roomname, $user_token, time() + (86400 * 30), "/", "", true, true);
        echo json_encode(['success' => true, 'message' => 'Joined room successfully']);
    } else {
        throw new Exception('Failed to join room');
    }
    $stmt->close();
    break;
            case 'typing_status':
                if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF token validation failed');
                }
                
                $is_typing = ($_POST['is_typing'] ?? 'false') === 'true';
                $success = $roomManager->updateTypingStatus($roomname, $_SESSION['username'], $is_typing);
                echo json_encode(['success' => $success]);
                break;
                
            case 'toggle_theme':
                $currentTheme = $_SESSION['dark_mode'] ?? false;
                $_SESSION['dark_mode'] = !$currentTheme;
                
                echo json_encode([
                    'success' => true, 
                    'dark_mode' => $_SESSION['dark_mode'],
                    'theme' => $_SESSION['dark_mode'] ? 'dark' : 'light'
                ]);
                break;
                
            case 'get_members':
                $members = $roomManager->getRoomMembers($roomname);
                echo json_encode(['success' => true, 'members' => $members]);
                break;
                
            case 'get_pending_requests':
                $isRoomCreator = $roomManager->isRoomCreator($roomname, $_SESSION['username']);
                if (!$isRoomCreator) {
                    throw new RuntimeException('Access denied: Room creator privileges required');
                }
                
                $requests = $roomManager->getPendingRequests($roomname);
                echo json_encode([
                    'success' => true, 
                    'requests' => $requests,
                    'count' => count($requests)
                ]);
                break;
                
            case 'remove_member':
                $isRoomCreator = $roomManager->isRoomCreator($roomname, $_SESSION['username']);
                if (!$isRoomCreator) {
                    throw new RuntimeException('Access denied: Room creator privileges required');
                }
                
                if (!$validator->validateUsername($_POST['username'] ?? '')) {
                    throw new InvalidArgumentException($validator->getFirstError());
                }
                
                $username = $security->sanitizeInput($_POST['username']);
                
                // Cannot remove self
                if ($username === $_SESSION['username']) {
                    throw new RuntimeException('Cannot remove yourself from the room');
                }
                
                $result = $roomManager->removeMember($roomname, $username);
                echo json_encode($result);
                break;
                
            case 'get_room_stats':
                $stats = $roomManager->getRoomStatistics($roomname);
                echo json_encode(['success' => true, 'stats' => $stats]);
                break;

            case 'get_messages':
                if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF token validation failed');
                }
                
                $last_id = intval($_POST['last_id'] ?? 0);
                
                $stmt = $conn->prepare("
                    SELECT m.id, m.username, m.msg, m.created_at, u.profile_photo
                    FROM messages m
                    LEFT JOIN users u ON m.username = u.username
                    WHERE m.roomname = ? AND m.id > ?
                    ORDER BY m.created_at ASC
                    LIMIT 50
                ");
                
                if (!$stmt) {
                    throw new RuntimeException('Failed to prepare messages statement: ' . $conn->error);
                }
                
                $stmt->bind_param("si", $roomname, $last_id);
                $stmt->execute();
                $result = $stmt->get_result();
                $messages = $result->fetch_all(MYSQLI_ASSOC);
                $stmt->close();
                
                $last_id = 0;
                if (!empty($messages)) {
                    $last_id = end($messages)['id'];
                }
                
                echo json_encode([
                    'success' => true,
                    'messages' => $messages,
                    'last_id' => $last_id
                ]);
                break;
                
            case 'get_typing_status':
                if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF token validation failed');
                }
                
                $stmt = $conn->prepare("
                    SELECT username FROM typing_indicators 
                    WHERE roomname = ? AND is_typing = 1 AND last_updated > DATE_SUB(NOW(), INTERVAL 5 SECOND)
                ");
                
                if (!$stmt) {
                    throw new RuntimeException('Failed to prepare typing status statement: ' . $conn->error);
                }
                
                $stmt->bind_param("s", $roomname);
                $stmt->execute();
                $result = $stmt->get_result();
                $typing_users = [];
                while ($row = $result->fetch_assoc()) {
                    $typing_users[] = $row['username'];
                }
                $stmt->close();
                
                echo json_encode([
                    'success' => true,
                    'typing_users' => $typing_users
                ]);
                break;
                
            case 'get_online_users':
                if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF token validation failed');
                }
                
                $stmt = $conn->prepare("
                    SELECT u.username 
                    FROM users u
                    JOIN room_users ru ON u.username = ru.username
                    WHERE ru.roomname = ? AND u.is_online = 1 AND u.last_seen > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
                ");
                
                if (!$stmt) {
                    throw new RuntimeException('Failed to prepare online users statement: ' . $conn->error);
                }
                
                $stmt->bind_param("s", $roomname);
                $stmt->execute();
                $result = $stmt->get_result();
                $online_users = [];
                while ($row = $result->fetch_assoc()) {
                    $online_users[] = $row['username'];
                }
                $stmt->close();
                
                echo json_encode([
                    'success' => true,
                    'online_users' => $online_users
                ]);
                break;
                
            case 'ping':
                $roomManager->updateUserOnlineStatus($_SESSION['username']);
                echo json_encode(['success' => true]);
                break;
            

            // Add these cases to the existing switch statement in the POST handler:

case 'approve_request':
    if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new RuntimeException('CSRF token validation failed');
    }
    
    $request_id = filter_var($_POST['request_id'] ?? 0, FILTER_VALIDATE_INT);
    if (!$request_id) {
        throw new InvalidArgumentException('Invalid request ID');
    }
    
    // Check if user is room creator
    if (!$roomManager->isRoomCreator($roomname, $_SESSION['username'])) {
        throw new RuntimeException('Access denied: Room creator privileges required');
    }
    
    // Get the request details
    $stmt = $conn->prepare("SELECT username, roomname FROM join_requests WHERE id = ? AND status = 'pending'");
    if (!$stmt) {
        throw new RuntimeException('Database error: ' . $conn->error);
    }
    $stmt->bind_param("i", $request_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $request = $result->fetch_assoc();
    $stmt->close();
    
    if (!$request) {
        throw new RuntimeException('Request not found or already processed');
    }
    
    // Update request status to approved
    $stmt = $conn->prepare("UPDATE join_requests SET status = 'approved', reviewed_at = NOW(), reviewed_by = ? WHERE id = ?");
    if (!$stmt) {
        throw new RuntimeException('Database error: ' . $conn->error);
    }
    $stmt->bind_param("si", $_SESSION['username'], $request_id);
    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Failed to approve request');
    }
    $stmt->close();
    
    // Add user to room
    $user_token = bin2hex(random_bytes(16));
    $stmt = $conn->prepare("INSERT INTO room_users (roomname, username, user_token, joined_at) VALUES (?, ?, ?, NOW())");
    if (!$stmt) {
        throw new RuntimeException('Database error: ' . $conn->error);
    }
    $stmt->bind_param("sss", $request['roomname'], $request['username'], $user_token);
    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Failed to add user to room');
    }
    $stmt->close();
    
    echo json_encode(['success' => true, 'message' => 'Request approved and user added to room']);
    break;

case 'deny_request':
    if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new RuntimeException('CSRF token validation failed');
    }
    
    $request_id = filter_var($_POST['request_id'] ?? 0, FILTER_VALIDATE_INT);
    if (!$request_id) {
        throw new InvalidArgumentException('Invalid request ID');
    }
    
    // Check if user is room creator
    if (!$roomManager->isRoomCreator($roomname, $_SESSION['username'])) {
        throw new RuntimeException('Access denied: Room creator privileges required');
    }
    
    // Check if request exists and is pending
    $stmt = $conn->prepare("SELECT id FROM join_requests WHERE id = ? AND status = 'pending'");
    if (!$stmt) {
        throw new RuntimeException('Database error: ' . $conn->error);
    }
    $stmt->bind_param("i", $request_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        $stmt->close();
        throw new RuntimeException('Request not found or already processed');
    }
    $stmt->close();
    
    // Update request status to denied
    $stmt = $conn->prepare("UPDATE join_requests SET status = 'denied', reviewed_at = NOW(), reviewed_by = ? WHERE id = ?");
    if (!$stmt) {
        throw new RuntimeException('Database error: ' . $conn->error);
    }
    $stmt->bind_param("si", $_SESSION['username'], $request_id);
    if (!$stmt->execute()) {
        $stmt->close();
        throw new RuntimeException('Failed to deny request');
    }
    $stmt->close();
    
    echo json_encode(['success' => true, 'message' => 'Request denied']);
    break;

case 'update_room_settings':
    if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new RuntimeException('CSRF token validation failed');
    }

    // Check if user is room creator
    if (!$roomManager->isRoomCreator($roomname, $_SESSION['username'])) {
        throw new RuntimeException('Access denied: Room creator privileges required');
    }

    // Process room settings update
    echo json_encode(['success' => true, 'message' => 'Settings updated']);
    break;

case 'decode_qr':
    if (!isset($_FILES['file'])) {
        echo json_encode(['success' => false, 'error' => 'No file uploaded']);
        break;
    }

    $file = $_FILES['file'];

    // Validate file
    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'error' => 'File upload error']);
        break;
    }

    // Check file type
    $allowedTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif'];
    if (!in_array($file['type'], $allowedTypes)) {
        echo json_encode(['success' => false, 'error' => 'Invalid file type']);
        break;
    }

    // For now, we'll return a mock response since we don't have QR decoding
    // In a real implementation, you'd use a QR decoding library or service
    echo json_encode([
        'success' => false,
        'error' => 'QR code decoding not implemented. Please use the room link instead.'
    ]);
    break;

case 'generate_qr_code':
    if (!$validator->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        throw new RuntimeException('CSRF token validation failed');
    }

    // Check if user is room creator or admin
    if (!$roomManager->isRoomCreator($roomname, $_SESSION['username']) && !$roomManager->isRoomAdmin($roomname, $_SESSION['username'])) {
        throw new RuntimeException('Access denied: Room admin privileges required');
    }

    // Generate QR code data
    $qrData = json_encode([
        'action' => 'join_room',
        'roomname' => $roomname,
        'timestamp' => time()
    ]);

    // Generate QR code using online API
    try {
        $qrDataEncoded = urlencode($qrData);
        $qrUrl = "https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={$qrDataEncoded}&format=png";

        echo json_encode([
            'success' => true,
            'qr_code_url' => $qrUrl,
            'room_name' => $roomname
        ]);
    } catch (Exception $e) {
        error_log('QR Code generation failed: ' . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Failed to generate QR code']);
    }
    break;
            default:
                throw new InvalidArgumentException('Invalid action: ' . $action);
        }
        
    } catch (Exception $e) {
        error_log("API Error: " . $e->getMessage());
        echo json_encode([
            'success' => false, 
            'error' => $e->getMessage(),
            'requires_login' => $e->getMessage() === 'Session expired. Please refresh the page.'
        ]);
    }
    
    exit();
}

// ===== REGULAR PAGE LOAD =====

// Validate roomname parameter for regular page load
if (!isset($_GET['roomname'])) {
    header("Location: index.php?error=room_required");
    exit();
}

$roomname = $_GET['roomname'] ?? '';

if (!$validator->validateRoomName($roomname)) {
    header("Location: index.php?error=invalid_room&message=" . urlencode($validator->getFirstError()));
    exit();
}

$roomname = $security->sanitizeInput($roomname);

// Verify room exists
if (!$roomManager->roomExists($roomname)) {
    header("Location: index.php?error=room_not_found&room=" . urlencode($roomname));
    exit();
}

// Verify user access via cookie token
$cookie_name = 'user_token_' . $roomname;
if (!isset($_COOKIE[$cookie_name])) {
    header("Location: index.php?error=access_denied&room=" . urlencode($roomname));
    exit();
}

$user_token = $_COOKIE[$cookie_name] ?? '';
$user_token = $security->sanitizeInput($user_token);

$user_access = $roomManager->getUserAccess($roomname, $user_token);

if (empty($user_access)) {
    // Clear invalid cookie
    setcookie($cookie_name, '', time() - 3600, '/', '', true, true);
    header("Location: index.php?error=invalid_token&room=" . urlencode($roomname));
    exit();
}

// Set session variables
$_SESSION['username'] = $user_access['username'];
$_SESSION['user_role'] = $user_access['role'];
$_SESSION['current_room'] = $roomname;
$_SESSION['user_token'] = $user_token;

// Update user online status
$roomManager->updateUserOnlineStatus($_SESSION['username']);

// Get room information
$roomInfo = $roomManager->getRoomInfo($roomname);
$isRoomCreator = $roomManager->isRoomCreator($roomname, $_SESSION['username']);

// Get room statistics
$roomStats = $roomManager->getRoomStatistics($roomname);

// Generate CSRF token for forms
$csrf_token = $security->generateCSRFToken();

// Set theme preference
$dark_mode = $_SESSION['dark_mode'] ?? false;
$current_theme = $dark_mode ? 'dark' : 'light';

// Get initial room members
$room_members = $roomManager->getRoomMembers($roomname);

// Get pending requests if room creator
$pending_requests = [];
if ($isRoomCreator) {
    $pending_requests = $roomManager->getPendingRequests($roomname);
}

?>
<!DOCTYPE html>
<html lang="en" data-theme="<?php echo $current_theme; ?>" data-room="<?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Galaxy Chat - Real-time chat room for <?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>">
    <meta name="keywords" content="chat, real-time, messaging, <?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>">
    <meta name="author" content="Galaxy Chat System">
    
    <title>Galaxy Chat - <?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?></title>
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="assets/images/favicon.ico">
    
    <!-- jQuery -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    
    <!-- Font Awesome -->
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

        /* ===== TYPOGRAPHY ===== */
        h1, h2, h3, h4, h5, h6 {
            margin-bottom: 0.5rem;
            font-weight: 600;
            line-height: 1.2;
            color: var(--text-primary);
        }

        h1 { font-size: 2.5rem; }
        h2 { font-size: 2rem; }
        h3 { font-size: 1.75rem; }
        h4 { font-size: 1.5rem; }
        h5 { font-size: 1.25rem; }
        h6 { font-size: 1rem; }

        p {
            margin-bottom: 1rem;
        }

        a {
            color: var(--accent-primary);
            text-decoration: none;
            transition: var(--transition);
        }

        a:hover {
            color: var(--accent-primary-hover);
            text-decoration: underline;
        }

        /* ===== LAYOUT COMPONENTS ===== */
        .app-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            background: var(--bg-primary);
        }

        /* Header */
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: var(--shadow-sm);
            z-index: var(--z-index-sticky);
            position: relative;
            transition: var(--transition);
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex: 1;
            min-width: 0;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        /* Room Info */
        .room-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .room-avatar {
            width: 3rem;
            height: 3rem;
            border-radius: var(--border-radius-lg);
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-purple));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.25rem;
            box-shadow: var(--shadow-sm);
            flex-shrink: 0;
            overflow: hidden;
        }

        .room-avatar img {
            width: 100%;
            height: 100%;
            border-radius: var(--border-radius-lg);
            object-fit: cover;
        }

        .room-details h1 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .room-meta {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-top: 0.25rem;
        }

        .room-stat {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .online-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .online-dot {
            width: 0.5rem;
            height: 0.5rem;
            border-radius: 50%;
            background: var(--accent-success);
            animation: pulse 2s infinite;
            box-shadow: 0 0 0 rgba(40, 167, 69, 0.4);
        }

        @keyframes pulse {
            0% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(40, 167, 69, 0.7);
            }
            70% {
                transform: scale(1);
                box-shadow: 0 0 0 10px rgba(40, 167, 69, 0);
            }
            100% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(40, 167, 69, 0);
            }
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
            position: relative;
            overflow: hidden;
        }

        .btn:focus {
            outline: 2px solid var(--accent-primary);
            outline-offset: 2px;
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none !important;
        }

        .btn-primary {
            background: var(--accent-primary);
            color: white;
        }

        .btn-primary:hover:not(:disabled) {
            background: var(--accent-primary-hover);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover:not(:disabled) {
            background: var(--border-color);
            transform: translateY(-1px);
        }

        .btn-success {
            background: var(--accent-success);
            color: white;
        }

        .btn-success:hover:not(:disabled) {
            background: #218838;
            transform: translateY(-1px);
        }

        .btn-danger {
            background: var(--accent-danger);
            color: white;
        }

        .btn-danger:hover:not(:disabled) {
            background: #c82333;
            transform: translateY(-1px);
        }

        .btn-warning {
            background: var(--accent-warning);
            color: var(--text-primary);
        }

        .btn-warning:hover:not(:disabled) {
            background: #e0a800;
            transform: translateY(-1px);
        }

        .btn-info {
            background: var(--accent-info);
            color: white;
        }

        .btn-info:hover:not(:disabled) {
            background: #138496;
            transform: translateY(-1px);
        }

        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.8125rem;
        }

        .btn-lg {
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
        }

        .btn-icon {
            padding: 0.5rem;
            width: 2.5rem;
            height: 2.5rem;
        }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            font-weight: 600;
            line-height: 1;
            border-radius: var(--border-radius-pill);
            background: var(--accent-secondary);
            color: white;
        }

        .badge-primary { background: var(--accent-primary); }
        .badge-success { background: var(--accent-success); }
        .badge-danger { background: var(--accent-danger); }
        .badge-warning { background: var(--accent-warning); color: var(--text-primary); }
        .badge-info { background: var(--accent-info); }

        .notification-badge {
            position: absolute;
            top: -0.5rem;
            right: -0.5rem;
            background: var(--accent-danger);
            color: white;
            border-radius: 50%;
            width: 1.25rem;
            height: 1.25rem;
            font-size: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            border: 2px solid var(--bg-secondary);
            animation: bounce 2s infinite;
        }

        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% {
                transform: translateY(0);
            }
            40% {
                transform: translateY(-5px);
            }
            60% {
                transform: translateY(-3px);
            }
        }

        /* Main Content Area */
        .main-content {
            display: flex;
            flex: 1;
            overflow: hidden;
            background: var(--bg-primary);
        }

        /* Sidebar */
        .sidebar {
            width: 300px;
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
        }

        .sidebar-header h3 {
            font-size: 1rem;
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

        .sidebar-section h4 {
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Members List */
        .members-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .member-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: var(--border-radius);
            transition: var(--transition);
            border: 1px solid transparent;
        }

        .member-item:hover {
            background: var(--bg-tertiary);
            border-color: var(--border-light);
        }

        .member-avatar {
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
            overflow: hidden;
        }

        .member-avatar img {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            object-fit: cover;
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

        .member-item.offline .online-status {
            background: var(--accent-secondary);
        }

        .member-item.away .online-status {
            background: var(--accent-warning);
        }

        .member-info {
            flex: 1;
            min-width: 0;
        }

        .member-name {
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 0.125rem;
        }

        .member-role {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .member-actions {
            display: flex;
            gap: 0.25rem;
            opacity: 0;
            transition: var(--transition);
        }

        .member-item:hover .member-actions {
            opacity: 1;
        }

        /* Chat Area */
        .chat-area {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-primary);
            position: relative;
        }

        /* Messages Container */
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background: var(--bg-primary);
        }

        .messages-container::-webkit-scrollbar {
            width: 6px;
        }

        .messages-container::-webkit-scrollbar-track {
            background: var(--bg-secondary);
            border-radius: 3px;
        }

        .messages-container::-webkit-scrollbar-thumb {
            background: var(--accent-secondary);
            border-radius: 3px;
        }

        .messages-container::-webkit-scrollbar-thumb:hover {
            background: var(--accent-primary);
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

        .message-system {
            align-self: center;
            background: var(--accent-warning);
            color: var(--text-primary);
            max-width: 80%;
            text-align: center;
            font-style: italic;
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

        .message-actions {
            display: flex;
            gap: 0.5rem;
            margin-top: 0.5rem;
            opacity: 0;
            transition: var(--transition);
        }

        .message:hover .message-actions {
            opacity: 1;
        }

        .message-action {
            background: none;
            border: none;
            color: inherit;
            opacity: 0.7;
            cursor: pointer;
            padding: 0.25rem;
            border-radius: var(--border-radius-sm);
            transition: var(--transition);
        }

        .message-action:hover {
            opacity: 1;
            background: rgba(255, 255, 255, 0.1);
        }

        /* Typing Indicator */
        .typing-indicator {
            padding: 0.5rem 1rem;
            font-style: italic;
            color: var(--text-secondary);
            font-size: 0.875rem;
            min-height: 2rem;
            transition: var(--transition);
        }

        .typing-dots {
            display: inline-flex;
            gap: 0.25rem;
        }

        .typing-dot {
            width: 0.5rem;
            height: 0.5rem;
            border-radius: 50%;
            background: var(--accent-secondary);
            animation: typingBounce 1.4s infinite ease-in-out;
        }

        .typing-dot:nth-child(1) { animation-delay: -0.32s; }
        .typing-dot:nth-child(2) { animation-delay: -0.16s; }

        @keyframes typingBounce {
            0%, 80%, 100% {
                transform: scale(0.8);
                opacity: 0.5;
            }
            40% {
                transform: scale(1);
                opacity: 1;
            }
        }

        /* Message Input */
        .message-input-container {
            padding: 1rem 1.5rem;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border-color);
            position: relative;
        }

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

        .message-input:disabled {
            background: var(--bg-tertiary);
            cursor: not-allowed;
        }

        .message-input-actions {
            display: flex;
            gap: 0.5rem;
            margin-top: 0.5rem;
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

        /* Modals */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--bg-overlay);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: var(--z-index-modal);
            opacity: 0;
            visibility: hidden;
            transition: var(--transition);
            padding: 1rem;
        }

        .modal.show {
            opacity: 1;
            visibility: visible;
        }

        .modal-content {
            background: var(--bg-primary);
            border-radius: var(--border-radius-lg);
            box-shadow: var(--shadow-lg);
            max-width: 500px;
            width: 100%;
            max-height: 90vh;
            overflow: hidden;
            transform: scale(0.9);
            transition: var(--transition);
            border: 1px solid var(--border-color);
        }

        .modal.show .modal-content {
            transform: scale(1);
        }

        .modal-lg .modal-content {
            max-width: 800px;
        }

        .input-group {
            display: flex;
            align-items: stretch;
        }

        .input-group .form-control {
            border-top-right-radius: 0;
            border-bottom-right-radius: 0;
            border-right: none;
        }

        .input-group .btn {
            border-top-left-radius: 0;
            border-bottom-left-radius: 0;
            margin-left: 0;
        }

        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-secondary);
        }

        .modal-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 0;
            width: 2rem;
            height: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--border-radius);
            transition: var(--transition);
        }

        .modal-close:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .modal-body {
            padding: 1.5rem;
            max-height: 60vh;
            overflow-y: auto;
        }

        .modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 0.75rem;
            justify-content: flex-end;
            background: var(--bg-secondary);
        }

        /* Forms */
        .form-group {
            margin-bottom: 1rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text-primary);
        }

        .form-control {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: var(--transition);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }

        .form-control:disabled {
            background: var(--bg-tertiary);
            cursor: not-allowed;
        }

        .form-text {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .form-check {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }

        .form-check-input {
            width: 1rem;
            height: 1rem;
        }

        .form-check-label {
            font-weight: normal;
            color: var(--text-primary);
            cursor: pointer;
        }

        /* Notifications */
        .notification-container {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: var(--z-index-toast);
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            max-width: 400px;
        }

        .notification {
            padding: 1rem 1.5rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            animation: notificationSlideIn 0.3s ease;
            border-left: 4px solid transparent;
        }

        @keyframes notificationSlideIn {
            from {
                opacity: 0;
                transform: translateX(100%);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .notification.success {
            background: var(--accent-success);
            color: white;
            border-left-color: #1e7e34;
        }

        .notification.error {
            background: var(--accent-danger);
            color: white;
            border-left-color: #bd2130;
        }

        .notification.warning {
            background: var(--accent-warning);
            color: var(--text-primary);
            border-left-color: #d39e00;
        }

        .notification.info {
            background: var(--accent-info);
            color: white;
            border-left-color: #117a8b;
        }

        .notification .icon {
            font-size: 1.25rem;
        }

        .notification .content {
            flex: 1;
        }

        .notification .close {
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            padding: 0.25rem;
            border-radius: var(--border-radius-sm);
            opacity: 0.7;
            transition: var(--transition);
        }

        .notification .close:hover {
            opacity: 1;
            background: rgba(255, 255, 255, 0.1);
        }

        /* Loading States */
        .loading {
            opacity: 0.6;
            pointer-events: none;
            position: relative;
        }

        .loading::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 1.5rem;
            height: 1.5rem;
            margin: -0.75rem 0 0 -0.75rem;
            border: 2px solid transparent;
            border-top: 2px solid var(--accent-primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .skeleton {
            background: linear-gradient(90deg, var(--bg-tertiary) 25%, var(--border-color) 50%, var(--bg-tertiary) 75%);
            background-size: 200% 100%;
            animation: skeletonLoading 1.5s infinite;
            border-radius: var(--border-radius);
        }

        @keyframes skeletonLoading {
            0% {
                background-position: 200% 0;
            }
            100% {
                background-position: -200% 0;
            }
        }

        /* Utility Classes */
        .hidden {
            display: none !important;
        }

        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }

        .text-center { text-align: center; }
        .text-left { text-align: left; }
        .text-right { text-align: right; }

        .text-truncate {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .d-flex { display: flex; }
        .d-none { display: none; }
        .d-block { display: block; }
        .d-inline { display: inline; }
        .d-inline-block { display: inline-block; }

        .flex-column { flex-direction: column; }
        .flex-row { flex-direction: row; }
        .flex-wrap { flex-wrap: wrap; }
        .flex-nowrap { flex-wrap: nowrap; }

        .justify-content-start { justify-content: flex-start; }
        .justify-content-end { justify-content: flex-end; }
        .justify-content-center { justify-content: center; }
        .justify-content-between { justify-content: space-between; }
        .justify-content-around { justify-content: space-around; }

        .align-items-start { align-items: flex-start; }
        .align-items-end { align-items: flex-end; }
        .align-items-center { align-items: center; }
        .align-items-baseline { align-items: baseline; }
        .align-items-stretch { align-items: stretch; }

        .w-100 { width: 100%; }
        .h-100 { height: 100%; }

        .m-0 { margin: 0; }
        .m-1 { margin: 0.25rem; }
        .m-2 { margin: 0.5rem; }
        .m-3 { margin: 1rem; }
        .m-4 { margin: 1.5rem; }
        .m-5 { margin: 3rem; }

        .p-0 { padding: 0; }
        .p-1 { padding: 0.25rem; }
        .p-2 { padding: 0.5rem; }
        .p-3 { padding: 1rem; }
        .p-4 { padding: 1.5rem; }
        .p-5 { padding: 3rem; }

        .rounded { border-radius: var(--border-radius); }
        .rounded-sm { border-radius: var(--border-radius-sm); }
        .rounded-lg { border-radius: var(--border-radius-lg); }
        .rounded-xl { border-radius: var(--border-radius-xl); }
        .rounded-pill { border-radius: var(--border-radius-pill); }
        .rounded-circle { border-radius: 50%; }

        .shadow { box-shadow: var(--shadow-sm); }
        .shadow-sm { box-shadow: var(--shadow-sm); }
        .shadow-md { box-shadow: var(--shadow-md); }
        .shadow-lg { box-shadow: var(--shadow-lg); }
        .shadow-none { box-shadow: none; }

        /* Responsive Design */
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                left: -100%;
                top: 0;
                height: 100%;
                z-index: var(--z-index-modal);
                width: 280px;
                box-shadow: var(--shadow-lg);
            }

            .sidebar.show {
                left: 0;
            }

            .message {
                max-width: 85%;
            }

            .header {
                padding: 0.75rem 1rem;
            }

            .room-meta {
                display: none;
            }

            .modal-content {
                margin: 1rem;
            }
        }

        @media (max-width: 576px) {
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

            .modal-content {
                width: 95%;
                margin: 0.5rem;
            }

            .notification-container {
                right: 0.5rem;
                left: 0.5rem;
                max-width: none;
            }
        }

        @media (max-width: 480px) {
            .header-right {
                gap: 0.5rem;
            }

            .btn span:not(.sr-only) {
                display: none;
            }

            .btn-icon {
                width: 2.25rem;
                height: 2.25rem;
            }

            .room-avatar {
                width: 2.5rem;
                height: 2.5rem;
                font-size: 1rem;
            }

            .room-details h1 {
                font-size: 1.125rem;
            }
        }

        /* Print Styles */
        @media print {
            .header,
            .sidebar,
            .message-input-container,
            .typing-indicator,
            .btn {
                display: none !important;
            }

            .main-content {
                display: block;
            }

            .messages-container {
                overflow: visible;
                height: auto;
            }

            .message {
                max-width: 100%;
                break-inside: avoid;
            }
        }

        /* High Contrast Mode Support */
        @media (prefers-contrast: high) {
            :root {
                --border-color: #000000;
                --shadow-sm: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.5);
            }

            .btn {
                border: 2px solid;
            }
        }

        /* Reduced Motion Support */
        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }

            .message {
                animation: none;
            }
        }

        /* Dark mode auto-detection */
        @media (prefers-color-scheme: dark) {
            :root:not([data-theme]) {
                --bg-primary: #121212;
                --bg-secondary: #1e1e1e;
                --bg-tertiary: #2d2d2d;
                --text-primary: #e9ecef;
                --text-secondary: #adb5bd;
            }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Header -->
        <header class="header">
            <div class="header-left">
                <div class="room-info">
                    <div class="room-avatar">
                        <?php if (!empty($roomInfo['display_photo'])): ?>
                            <img src="<?php echo htmlspecialchars($roomInfo['display_photo'], ENT_QUOTES, 'UTF-8'); ?>" 
                                 alt="<?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>"
                                 onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                            <span style="display: none;"><?php echo strtoupper(substr($roomname, 0, 2)); ?></span>
                        <?php else: ?>
                            <?php echo strtoupper(substr($roomname, 0, 2)); ?>
                        <?php endif; ?>
                    </div>
                    <div class="room-details">
                        <h1><?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?></h1>
                        <div class="room-meta">
                            <div class="room-stat">
                                <span class="online-indicator">
                                    <span class="online-dot"></span>
                                    <span id="online-count"><?php echo $roomStats['online_members']; ?></span> online
                                </span>
                            </div>
                            <div class="room-stat">
                                <i class="fas fa-users"></i>
                                <span id="member-count"><?php echo $roomStats['active_members']; ?></span> members
                            </div>
                            <div class="room-stat">
                                <i class="fas fa-comment"></i>
                                <span id="message-count"><?php echo $roomStats['total_messages']; ?></span> messages
                            </div>
                        </div>
                    </div>
                </div>
            </div>

<div class="header-right">
    <?php if ($isRoomCreator): ?>
    <div style="position: relative;">
        <button class="btn btn-secondary" onclick="toggleNotifications()" id="notifications-btn">
            <i class="fas fa-bell"></i>
            <span class="sr-only">Notifications</span>
            <span id="notification-badge" class="notification-badge <?php echo empty($pending_requests) ? 'hidden' : ''; ?>">
                <?php echo count($pending_requests); ?>
            </span>
        </button>
    </div>
    
    <button class="btn btn-secondary" onclick="openRoomSettings()" id="settings-btn">
        <i class="fas fa-cog"></i>
        <span>Settings</span>
    </button>
    
    <!-- ADD THIS BUTTON -->
    <button class="btn btn-primary" onclick="openInviteModal()" id="invite-btn">
        <i class="fas fa-user-plus"></i>
        <span>Invite</span>
    </button>

    <?php if ($isRoomCreator || $roomManager->isRoomAdmin($roomname, $_SESSION['username'])): ?>
    <button class="btn btn-info" onclick="generateQRCode()" id="qr-btn">
        <i class="fas fa-qrcode"></i>
        <span>QR Code</span>
    </button>
    <?php endif; ?>
    <?php endif; ?>
    
    <button class="btn btn-secondary" onclick="toggleTheme()" id="theme-toggle-btn">
        <i class="fas fa-moon"></i>
        <span><?php echo $dark_mode ? 'Light' : 'Dark'; ?></span>
    </button>
    
    <button class="btn btn-secondary" onclick="toggleSidebar()" id="sidebar-toggle-btn">
        <i class="fas fa-users"></i>
        <span>Members</span>
    </button>
    
    <button class="btn btn-secondary" onclick="openScanModal()" id="scan-btn">
        <i class="fas fa-camera"></i>
        <span>Scan QR</span>
    </button>
    
    <button class="btn btn-primary" onclick="leaveRoom()" id="leave-btn">
        <i class="fas fa-sign-out-alt"></i>
        <span>Leave</span>
    </button>
</div>
        </header>

        <!-- Main Content -->
        <div class="main-content">
            <!-- Sidebar -->
            <aside class="sidebar" id="sidebar">
                <div class="sidebar-header">
                    <h3>Room Members</h3>
                    <button class="btn btn-icon btn-secondary" onclick="toggleSidebar()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="sidebar-content">
                    <div class="sidebar-section">
                        <h4>Online Members</h4>
                        <div class="members-list" id="online-members-list">
                            <!-- Online members will be loaded here -->
                        </div>
                    </div>
                    
                    <div class="sidebar-section">
                        <h4>All Members</h4>
                        <div class="members-list" id="all-members-list">
                            <!-- All members will be loaded here -->
                        </div>
                    </div>
                </div>
            </aside>

            <!-- Chat Area -->
            <main class="chat-area">
                <div class="messages-container" id="messages-container">
                    <div class="text-center p-4">
                        <div class="skeleton" style="height: 20px; width: 200px; margin: 0 auto 1rem;"></div>
                        <div class="skeleton" style="height: 16px; width: 150px; margin: 0 auto;"></div>
                    </div>
                </div>

                <div class="typing-indicator" id="typing-indicator" style="display: none;">
                    <span id="typing-text"></span>
                    <div class="typing-dots">
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                    </div>
                </div>

                <div class="message-input-container">
                    <form class="message-form" id="message-form">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="message-input-wrapper">
                            <textarea 
                                class="message-input" 
                                id="message-input" 
                                placeholder="Type your message here... (Press Enter to send, Shift+Enter for new line)" 
                                rows="1"
                                maxlength="1000"
                                aria-label="Type your message"
                            ></textarea>
                            <div class="message-input-actions">
                                <small class="text-muted" id="char-count">0/1000</small>
                            </div>
                        </div>
                        <button type="submit" class="send-button" id="send-button" disabled aria-label="Send message">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </form>
                </div>
            </main>
        </div>
    </div>

    <!-- Room Settings Modal -->
    <div class="modal" id="room-settings-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Room Settings</h2>
                <button class="modal-close" onclick="closeRoomSettings()" aria-label="Close settings">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="room-settings-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    
                    <div class="form-group">
                        <label class="form-label" for="room-name">Room Name</label>
                        <input type="text" class="form-control" id="room-name" name="room_name" 
                               value="<?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>" 
                               maxlength="50" required>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="room-description">Room Description</label>
                        <textarea class="form-control" id="room-description" name="room_description" 
                                  rows="3" placeholder="Enter a description for this room..."
                                  maxlength="500"><?php echo htmlspecialchars($roomInfo['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                        <div class="form-text">Describe the purpose or topic of this room.</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="room-privacy">Privacy Settings</label>
                        <select class="form-control" id="room-privacy" name="privacy">
                            <option value="public" <?php echo empty($roomInfo['is_private']) ? 'selected' : ''; ?>>Public - Anyone can join</option>
                            <option value="private" <?php echo !empty($roomInfo['is_private']) ? 'selected' : ''; ?>>Private - Invitation only</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="max-members">Maximum Members</label>
                        <input type="number" class="form-control" id="max-members" name="max_members" 
                               value="<?php echo $roomInfo['max_members'] ?? 100; ?>" min="2" max="1000">
                        <div class="form-text">Maximum number of members allowed in this room.</div>
                    </div>

                    <div class="form-group">
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input" id="require-approval" name="require_approval">
                            <label class="form-check-label" for="require-approval">Require approval for new members</label>
                        </div>
                        <div class="form-text">New members will need to be approved by room admins.</div>
                    </div>

                    <div class="form-group">
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input" id="allow-guests" name="allow_guests" checked>
                            <label class="form-check-label" for="allow-guests">Allow guest access</label>
                        </div>
                        <div class="form-text">Allow temporary guest access without full membership.</div>
                    </div>

                    <div class="form-group">
                        <div class="form-check">
                            <input type="checkbox" class="form-check-input" id="enable-qr-codes" name="enable_qr_codes" checked>
                            <label class="form-check-label" for="enable-qr-codes">Enable QR code sharing</label>
                        </div>
                        <div class="form-text">Allow room admins to generate QR codes for easy room sharing.</div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="welcome-message">Welcome Message</label>
                        <textarea class="form-control" id="welcome-message" name="welcome_message" 
                                  rows="2" placeholder="Welcome message for new members..."
                                  maxlength="1000"><?php echo htmlspecialchars($roomInfo['welcome_message'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>
                        <div class="form-text">This message will be shown to new members when they join.</div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeRoomSettings()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="saveRoomSettings()">Save Changes</button>
            </div>
        </div>
    </div>

    <!-- Notifications Modal -->
    <div class="modal" id="notifications-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Pending Join Requests</h2>
                <button class="modal-close" onclick="closeNotifications()" aria-label="Close notifications">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div id="requests-list">
                    <?php if (empty($pending_requests)): ?>
                        <div class="text-center p-4">
                            <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                            <p class="text-muted">No pending requests</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($pending_requests as $request): ?>
                            <div class="member-item" data-request-id="<?php echo $request['id']; ?>">
                                <div class="member-avatar">
                                    <?php echo strtoupper(substr($request['username'], 0, 1)); ?>
                                </div>
                                <div class="member-info">
                                    <div class="member-name"><?php echo htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8'); ?></div>
                                    <div class="member-role">Requested <?php echo date('M j, g:i A', strtotime($request['requested_at'])); ?></div>
                                </div>
                                <div class="member-actions">
                                    <button class="btn btn-success btn-sm" onclick="approveRequest(<?php echo $request['id']; ?>)">
                                        <i class="fas fa-check"></i>
                                    </button>
                                    <button class="btn btn-danger btn-sm" onclick="denyRequest(<?php echo $request['id']; ?>)">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Invite Member Modal -->
    <div class="modal" id="invite-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Invite Member</h2>
                <button class="modal-close" onclick="closeInviteModal()" aria-label="Close invite modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="invite-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <div class="form-group">
                        <label class="form-label" for="invite-username">Username</label>
                        <input type="text" class="form-control" id="invite-username" name="username"
                               placeholder="Enter username to invite" maxlength="30" required>
                        <div class="form-text">Enter the exact username of the person you want to invite.</div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeInviteModal()">Cancel</button>
                <button type="button" class="btn btn-primary" onclick="sendInvitation()">Send Invitation</button>
            </div>
        </div>
    </div>
    
    <!-- QR Code Modal -->
    <div class="modal" id="qr-modal">
        <div class="modal-content modal-lg">
            <div class="modal-header">
                <h2>Room QR Code</h2>
                <button class="modal-close" onclick="closeQRModal()" aria-label="Close QR code modal">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="text-center">
                    <p class="mb-3">Scan this QR code to join the room "<?php echo htmlspecialchars($roomname, ENT_QUOTES, 'UTF-8'); ?>"</p>
                    <div id="qr-code-container" class="mb-3">
                        <div class="skeleton" style="width: 300px; height: 300px; margin: 0 auto;"></div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Room Link</label>
                        <div class="input-group">
                            <input type="text" class="form-control" id="room-link" readonly
                                   value="<?php echo htmlspecialchars('http://' . $_SERVER['HTTP_HOST'] . '/room.php?roomname=' . urlencode($roomname), ENT_QUOTES, 'UTF-8'); ?>">
                            <button class="btn btn-secondary" onclick="copyRoomLink()" type="button">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <div class="form-text">Share this link or QR code with others to let them join the room.</div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="closeQRModal()">Close</button>
                <button type="button" class="btn btn-primary" onclick="downloadQRCode()">
                    <i class="fas fa-download"></i> Download QR Code
                </button>
            </div>
        </div>
    </div>
    
    <!-- Scan QR Code Modal -->
    <div class="modal" id="scan-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Scan QR Code</h2>
                <button class="modal-close" onclick="closeScanModal()" aria-label="Close scan modal">
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

    <!-- Notifications Container -->
    <div class="notification-container" id="notification-container"></div>

    <script>
        /**
         * Galaxy Chat - Advanced Chat Application
         * Complete client-side implementation with real-time features
         */
        class ChatApp {
            constructor() {
                // Core properties
                this.roomName = '<?php echo $roomname; ?>';
                this.username = '<?php echo $_SESSION['username']; ?>';
                this.userRole = '<?php echo $_SESSION['user_role']; ?>';
                this.isRoomCreator = <?php echo $isRoomCreator ? 'true' : 'false'; ?>;
                this.csrfToken = '<?php echo $csrf_token; ?>';
                
                // State management
                this.lastMessageId = 0;
                this.isTyping = false;
                this.typingTimer = null;
                this.typingDelay = 2000;
                
                // Configuration
                this.config = {
                    messageRefreshRate: 3000,
                    typingRefreshRate: 1000,
                    onlineUsersRefreshRate: 10000,
                    membersRefreshRate: 15000,
                    requestsRefreshRate: 20000
                };
                
                // Intervals storage
                this.intervals = new Map();
                
                // Initialize the application
                this.initialize();
            }

            /**
             * Initialize the chat application
             */
            initialize() {
                try {
                    this.setupEventListeners();
                    this.loadInitialData();
                    this.startPollingIntervals();
                    
                    console.log('Galaxy Chat initialized successfully');
                } catch (error) {
                    console.error('Failed to initialize chat app:', error);
                    this.showNotification('Failed to initialize chat. Please refresh the page.', 'error');
                }
            }

            /**
 * Open invite member modal
 */
openInviteModal() {
    $('#invite-modal').addClass('show');
    $('#invite-username').focus();
}

/**
 * Close invite member modal  
 */
closeInviteModal() {
    $('#invite-modal').removeClass('show');
    $('#invite-form')[0].reset();
}
            /**
             * Set up all event listeners
             */
            setupEventListeners() {
                const self = this;
                
                // Message form
                $('#message-form').on('submit', function(e) { 
                    e.preventDefault();
                    self.handleMessageSubmit(e); 
                });
                
                $('#message-input').on('input', function() { 
                    self.handleMessageInput(); 
                });
                
                $('#message-input').on('keydown', function(e) { 
                    self.handleMessageKeydown(e); 
                });
                
                // Character count
                $('#message-input').on('input', function() { 
                    self.updateCharCount(); 
                });
                
                // Window events
                $(window).on('beforeunload', function() { 
                    self.handlePageUnload(); 
                });
                
                $(window).on('focus', function() { 
                    self.handleWindowFocus(); 
                });
                
                // Modal events
                $('#room-settings-modal').on('click', function(e) {
                    if (e.target === e.currentTarget) self.closeRoomSettings();
                });
                
                $('#notifications-modal').on('click', function(e) {
                    if (e.target === e.currentTarget) self.closeNotifications();
                });
                
                $('#invite-modal').on('click', function(e) {
                    if (e.target === e.currentTarget) self.closeInviteModal();
                });
                
                $('#qr-modal').on('click', function(e) {
                    if (e.target === e.currentTarget) self.closeQRModal();
                });
                
                $('#scan-modal').on('click', function(e) {
                    if (e.target === e.currentTarget) self.closeScanModal();
                });
                
                // Keyboard shortcuts
                $(document).on('keydown', function(e) { 
                    self.handleKeyboardShortcuts(e); 
                });
                
                // Visibility change
                document.addEventListener('visibilitychange', function() { 
                    self.handleVisibilityChange(); 
                });
            }
            /**
             * Load initial data for the chat room
             */
            async loadInitialData() {
                try {
                    // Load messages first
                    await this.loadMessages(true);
                    
                    // Then load other data
                    await Promise.all([
                        this.loadRoomMembers(),
                        this.loadOnlineUsers(),
                        this.loadRoomStatistics()
                    ]);
                    
                    // Scroll to bottom after initial load
                    this.scrollToBottom();
                    
                } catch (error) {
                    console.error('Error loading initial data:', error);
                    this.showNotification('Error loading chat data', 'error');
                }
            }

            /**
             * Start all polling intervals
             */
            startPollingIntervals() {
                // Message polling
                this.setInterval('messages', () => this.loadMessages(), this.config.messageRefreshRate);
                
                // Typing indicators polling
                this.setInterval('typing', () => this.loadTypingStatus(), this.config.typingRefreshRate);
                
                // Online users polling
                this.setInterval('online', () => this.loadOnlineUsers(), this.config.onlineUsersRefreshRate);
                
                // Room members polling
                this.setInterval('members', () => this.loadRoomMembers(), this.config.membersRefreshRate);
                
                // Requests polling (for room creators only)
                if (this.isRoomCreator) {
                    this.setInterval('requests', () => this.loadPendingRequests(), this.config.requestsRefreshRate);
                }
                
                // Online status ping
                this.setInterval('ping', () => this.sendPing(), 60000);
            }

            /**
             * Set an interval with proper cleanup
             */
            setInterval(name, callback, delay) {
                const intervalId = setInterval(callback, delay);
                this.intervals.set(name, intervalId);
            }

            /**
             * Clear all intervals
             */
            clearIntervals() {
                for (const [name, intervalId] of this.intervals) {
                    clearInterval(intervalId);
                }
                this.intervals.clear();
            }

            // ===== MESSAGE MANAGEMENT =====

            /**
             * Make an API call to the server
             */
            async apiCall(data) {
                try {
                    // Create URLSearchParams for the data
                    const params = new URLSearchParams();
                    
                    // Add all data to params
                    for (const key in data) {
                        if (data[key] !== undefined && data[key] !== null) {
                            params.append(key, data[key]);
                        }
                    }
                    
                    // Add required parameters if not present
                    if (!params.has('csrf_token')) {
                        params.append('csrf_token', this.csrfToken);
                    }
                    if (!params.has('roomname')) {
                        params.append('roomname', this.roomName);
                    }

                    const response = await fetch('room.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: params.toString()
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const text = await response.text();
                    
                    // Check if we got HTML instead of JSON (authentication issue)
                    if (text.trim().startsWith('<!DOCTYPE') || text.includes('<html') || text.includes('Welcome to Galaxy Chat')) {
                        console.error('Received HTML instead of JSON - likely authentication issue');
                        this.handleAuthenticationError();
                        throw new Error('Authentication required');
                    }
                    
                    // Try to parse as JSON
                    try {
                        const result = JSON.parse(text);
                        return result;
                    } catch (parseError) {
                        console.error('Failed to parse JSON response. Response was:', text.substring(0, 200));
                        throw new Error('Invalid JSON response from server');
                    }
                } catch (error) {
                    console.error('API call failed:', error);
                    
                    // Don't show notification for authentication errors to avoid spam
                    if (!error.message.includes('Authentication')) {
                        this.showNotification('Connection error. Please refresh the page.', 'error');
                    }
                    
                    throw error;
                }
            }

            /**
             * Handle authentication errors
             */
            handleAuthenticationError() {
                console.error('Authentication error detected');
                
                // Show a user-friendly message
                this.showNotification('Your session has expired. Please refresh the page to continue.', 'warning');
                
                // Disable the message input
                this.setMessageInputState(false);
                
                // Stop all polling intervals
                this.clearIntervals();
            }

            /**
             * Load messages from the server
             */
            async loadMessages(initialLoad = false) {
                try {
                    const response = await this.apiCall({
                        action: 'get_messages',
                        last_id: initialLoad ? 0 : this.lastMessageId
                    });

                    if (response && response.success && response.messages && response.messages.length > 0) {
                        if (initialLoad) {
                            this.displayMessages(response.messages);
                        } else {
                            this.displayNewMessages(response.messages);
                        }
                        this.lastMessageId = response.last_id || this.lastMessageId;
                    } else if (initialLoad) {
                        this.showWelcomeMessage();
                    }

                } catch (error) {
                    console.error('Error loading messages:', error);
                }
            }

            /**
             * Display all messages (initial load)
             */
            displayMessages(messages) {
                const container = $('#messages-container');
                container.empty();

                if (messages.length === 0) {
                    this.showWelcomeMessage();
                    return;
                }

                messages.forEach(message => {
                    container.append(this.createMessageElement(message));
                });
            }

            /**
             * Display new messages (subsequent loads)
             */
            displayNewMessages(messages) {
                const container = $('#messages-container');
                
                messages.forEach(message => {
                    // Check if message already exists
                    if (!container.find(`[data-message-id="${message.id}"]`).length) {
                        container.append(this.createMessageElement(message));
                    }
                });

                this.scrollToBottomIfNear();
            }

            /**
             * Create a message element
             */
            createMessageElement(message) {
                const isOutgoing = message.username === this.username;
                const isSystem = message.type === 'system';
                const messageClass = isSystem ? 'message-system' : 
                                   isOutgoing ? 'message-outgoing' : 'message-incoming';
                const timestamp = this.formatTimestamp(message.timestamp || message.created_at);

                // Escape the message content for safety
                const escapedMessage = this.escapeHtml(message.msg || message.message);
                const escapedUsername = this.escapeHtml(message.username);

                return `
                    <div class="message ${messageClass}" data-message-id="${message.id}">
                        <div class="message-header">
                            <span class="message-sender">${escapedUsername}</span>
                            <span class="message-time">${timestamp}</span>
                        </div>
                        <div class="message-content">${escapedMessage}</div>
                        <div class="message-actions">
                            <button class="message-action" onclick="window.chatApp.copyMessage('${escapedMessage.replace(/'/g, "\\'")}')" title="Copy message">
                                <i class="fas fa-copy"></i>
                            </button>
                            ${!isSystem && !isOutgoing ? `
                                <button class="message-action" onclick="window.chatApp.replyToMessage('${escapedUsername}', '${escapedMessage.replace(/'/g, "\\'")}')" title="Reply">
                                    <i class="fas fa-reply"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            }

            /**
             * Show welcome message for empty rooms
             */
            showWelcomeMessage() {
                const container = $('#messages-container');
                const welcomeMessage = `
                    <div class="text-center p-5">
                        <i class="fas fa-comments fa-3x text-muted mb-3"></i>
                        <h3 class="text-muted">Welcome to ${this.escapeHtml(this.roomName)}</h3>
                        <p class="text-muted">No messages yet. Start the conversation!</p>
                    </div>
                `;
                container.html(welcomeMessage);
            }

            /**
             * Handle message form submission
             */
            async handleMessageSubmit(e) {
                const messageInput = $('#message-input');
                const message = messageInput.val().trim();
                
                if (!message) return;

                // Disable input during send
                this.setMessageInputState(false);

                try {
                    const response = await this.apiCall({
                        action: 'send_message',
                        message: message
                    });

                    if (response && response.success) {
                        messageInput.val('');
                        this.updateCharCount();
                        this.updateTypingStatus(false);
                        this.isTyping = false;
                        
                        // Reload messages to show the new one
                        await this.loadMessages();
                    } else {
                        this.showNotification('Failed to send message: ' + (response ? response.error : 'Unknown error'), 'error');
                    }
                } catch (error) {
                    this.showNotification('Error sending message. Please try again.', 'error');
                    console.error('Message send error:', error);
                } finally {
                    this.setMessageInputState(true);
                    messageInput.focus();
                }
            }

            /**
             * Handle message input changes
             */
            handleMessageInput() {
                const messageInput = $('#message-input');
                const button = $('#send-button');
                
                // Update send button state
                button.prop('disabled', messageInput.val().trim() === '');

                // Handle typing indicator
                if (!this.isTyping) {
                    this.isTyping = true;
                    this.updateTypingStatus(true);
                }

                clearTimeout(this.typingTimer);
                this.typingTimer = setTimeout(() => {
                    this.isTyping = false;
                    this.updateTypingStatus(false);
                }, this.typingDelay);
            }

            /**
             * Handle message input keydown events
             */
            handleMessageKeydown(e) {
                // Send on Enter (without Shift)
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.handleMessageSubmit(e);
                }
                
                // Clear typing indicator on Escape
                if (e.key === 'Escape') {
                    this.isTyping = false;
                    this.updateTypingStatus(false);
                }
            }

            /**
             * Update character count
             */
            updateCharCount() {
                const messageInput = $('#message-input');
                const charCount = $('#char-count');
                const count = messageInput.val().length;
                
                charCount.text(`${count}/1000`);
                
                // Add warning class when approaching limit
                if (count > 900) {
                    charCount.addClass('text-danger');
                } else {
                    charCount.removeClass('text-danger');
                }
            }

            /**
             * Set message input state
             */
            setMessageInputState(enabled) {
                const input = $('#message-input');
                const button = $('#send-button');
                
                if (enabled) {
                    input.prop('disabled', false);
                    button.prop('disabled', input.val().trim() === '');
                } else {
                    input.prop('disabled', true);
                    button.prop('disabled', true);
                }
            }

            /**
             * Update typing status on server
             */
            async updateTypingStatus(isTyping) {
                try {
                    await this.apiCall({
                        action: 'typing_status',
                        is_typing: isTyping
                    });
                } catch (error) {
                    console.error('Error updating typing status:', error);
                }
            }

            /**
             * Load typing status from server
             */
            async loadTypingStatus() {
                try {
                    const response = await this.apiCall({
                        action: 'get_typing_status'
                    });

                    const indicator = $('#typing-indicator');
                    const typingText = $('#typing-text');
                    
                    if (response && response.success && response.typing_users && response.typing_users.length > 0) {
                        const users = response.typing_users.filter(user => user !== this.username);
                        if (users.length > 0) {
                            const text = users.length === 1 ? 
                                `${users[0]} is typing` : 
                                `${users.slice(0, 2).join(', ')}${users.length > 2 ? ' and others' : ''} are typing`;
                            
                            typingText.text(text);
                            indicator.show();
                        } else {
                            indicator.hide();
                        }
                    } else {
                        indicator.hide();
                    }
                } catch (error) {
                    console.error('Error loading typing status:', error);
                }
            }

            // ===== ROOM MANAGEMENT =====

            /**
             * Load room members
             */
            async loadRoomMembers() {
                try {
                    const response = await this.apiCall({
                        action: 'get_members'
                    });

                    if (response && response.success && response.members) {
                        this.displayRoomMembers(response.members);
                    }
                } catch (error) {
                    console.error('Error loading room members:', error);
                }
            }

            /**
             * Display room members in the sidebar
             */
            displayRoomMembers(members) {
                const onlineContainer = $('#online-members-list');
                const allContainer = $('#all-members-list');
                
                let onlineHtml = '';
                let allHtml = '';
                
                const onlineMembers = members.filter(m => m.status === 'online' || m.is_online);
                const offlineMembers = members.filter(m => !m.is_online && m.status !== 'online');

                // Online members
                if (onlineMembers.length > 0) {
                    onlineMembers.forEach(member => {
                        onlineHtml += this.createMemberElement(member);
                    });
                } else {
                    onlineHtml = '<div class="text-muted text-center p-2">No members online</div>';
                }

                // All members
                [...onlineMembers, ...offlineMembers].forEach(member => {
                    allHtml += this.createMemberElement(member);
                });

                onlineContainer.html(onlineHtml);
                allContainer.html(allHtml);
                
                // Update member count
                $('#member-count').text(members.length);
            }

            /**
             * Create a member list element
             */
            createMemberElement(member) {
                const isOnline = member.status === 'online' || member.is_online;
                const isCurrentUser = member.username === this.username;
                const statusClass = isOnline ? '' : 'offline';
                const roleText = member.role === 'admin' ? 'Admin' : 'Member';
                const lastSeen = isOnline ? 'Online' : this.formatRelativeTime(member.last_seen);

                return `
                    <div class="member-item ${statusClass}" data-username="${member.username}">
                        <div class="member-avatar">
                            ${this.escapeHtml(member.username.charAt(0).toUpperCase())}
                            <div class="online-status"></div>
                        </div>
                        <div class="member-info">
                            <div class="member-name">
                                ${this.escapeHtml(member.username)} ${isCurrentUser ? '(You)' : ''}
                            </div>
                            <div class="member-role">${roleText} • ${lastSeen}</div>
                        </div>
                        <div class="member-actions">
                            ${!isCurrentUser && this.isRoomCreator ? `
                                <button class="btn btn-danger btn-sm" onclick="window.chatApp.removeMember('${this.escapeHtml(member.username)}')" title="Remove member">
                                    <i class="fas fa-user-times"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            }

            /**
             * Load online users count
             */
            async loadOnlineUsers() {
                try {
                    const response = await this.apiCall({
                        action: 'get_online_users'
                    });

                    if (response && response.success && response.online_users) {
                        $('#online-count').text(response.online_users.length);
                    }
                } catch (error) {
                    console.error('Error loading online users:', error);
                }
            }

            /**
             * Load room statistics
             */
            async loadRoomStatistics() {
                try {
                    const response = await this.apiCall({
                        action: 'get_room_stats'
                    });

                    if (response && response.success && response.stats) {
                        // Update statistics in the header
                        $('#message-count').text(response.stats.total_messages || 0);
                        $('#member-count').text(response.stats.active_members || 0);
                        $('#online-count').text(response.stats.online_members || 0);
                    }
                } catch (error) {
                    console.error('Error loading room statistics:', error);
                }
            }

            // ===== ROOM CREATOR FEATURES =====

            /**
             * Load pending join requests
             */
            async loadPendingRequests() {
                if (!this.isRoomCreator) return;

                try {
                    const response = await this.apiCall({
                        action: 'get_pending_requests'
                    });

                    if (response && response.success) {
                        this.displayPendingRequests(response.requests || []);
                        this.updateNotificationBadge(response.count || 0);
                    }
                } catch (error) {
                    console.error('Error loading pending requests:', error);
                }
            }

            /**
             * Display pending requests
             */
            displayPendingRequests(requests) {
                const container = $('#requests-list');
                
                if (requests.length === 0) {
                    container.html(`
                        <div class="text-center p-4">
                            <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                            <p class="text-muted">No pending requests</p>
                        </div>
                    `);
                    return;
                }

                let html = '';
                requests.forEach(request => {
                    html += `
                        <div class="member-item" data-request-id="${request.id}">
                            <div class="member-avatar">
                                ${this.escapeHtml(request.username.charAt(0).toUpperCase())}
                            </div>
                            <div class="member-info">
                                <div class="member-name">${this.escapeHtml(request.username)}</div>
                                <div class="member-role">Requested ${this.formatRelativeTime(request.requested_at)}</div>
                            </div>
                            <div class="member-actions">
                                <button class="btn btn-success btn-sm" onclick="window.chatApp.approveRequest(${request.id})" title="Approve">
                                    <i class="fas fa-check"></i>
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="window.chatApp.denyRequest(${request.id})" title="Deny">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        </div>
                    `;
                });

                container.html(html);
            }

            /**
             * Approve a join request
             */

            function processRequest(requestId, action) {
    // 'action' should be 'approve' or 'deny'
    const actionText = action === 'approve' ? 'Approving' : 'Denying';
    console.log(`${actionText} request:`, requestId);

    $.ajax({
        url: 'manage_request.php', // New single file
        type: 'POST',
        data: {
            request_id: requestId,
            action: action
        },
        dataType: 'json',
        success: function(response) {
            console.log(`${action} response:`, response);
            if (response.success) {
                // Remove notification item
                $(`.notification-item[data-request-id="${requestId}"]`).fadeOut(300, function() {
                    $(this).remove();
                    loadPendingRequests(); // Update count
                });
                
                if (action === 'approve') loadRoomMembers(); // Refresh list if approved
                
                // Show success message
                const emoji = action === 'approve' ? '✅' : '❌';
                showMessage(action === 'approve' ? 'success' : 'error', `${emoji} ${response.message}`);
            } else {
                alert('Error: ' + (response.error || 'Operation failed'));
            }
        },
        error: function(xhr, status, error) {
            console.error(`AJAX Error ${action}:`, status, error);
            alert(`Failed to ${action} request.`);
        }
    });
}

// Wrapper functions to keep your HTML onclick="approveRequest(...)" working
function approveRequest(requestId) {
    processRequest(requestId, 'approve');
}

function denyRequest(requestId) {
    processRequest(requestId, 'deny');
}

            /**
             * Remove a member from the room
             */
            async removeMember(username) {
                if (!confirm(`Are you sure you want to remove ${username} from the room?`)) {
                    return;
                }

                try {
                    const response = await this.apiCall({
                        action: 'remove_member',
                        username: username
                    });

                    if (response && response.success) {
                        this.showNotification(`Member ${username} removed successfully`, 'success');
                        this.loadRoomMembers();
                    } else {
                        this.showNotification('Error removing member: ' + (response ? response.error : 'Unknown error'), 'error');
                    }
                } catch (error) {
                    this.showNotification('Error removing member', 'error');
                }
            }

            /**
             * Open invite member modal
             */
            openInviteModal() {
                $('#invite-modal').addClass('show');
                $('#invite-username').focus();
            }

            /**
             * Close invite member modal
             */
            closeInviteModal() {
                $('#invite-modal').removeClass('show');
                $('#invite-form')[0].reset();
            }

            /**
             * Send invitation to a user
             */
            async sendInvitation() {
                const username = $('#invite-username').val().trim();
            
                if (!username) {
                    this.showNotification('Please enter a username', 'warning');
                    return;
                }
            
                try {
                    const response = await this.apiCall({
                        action: 'invite_member',
                        roomname: this.roomName,
                        username: username
                    });
            
                    if (response && response.success) {
                        this.showNotification('Invitation sent successfully', 'success');
                        this.closeInviteModal();
                    } else {
                        this.showNotification('Error sending invitation: ' + (response ? response.error : 'Unknown error'), 'error');
                    }
                } catch (error) {
                    this.showNotification('Error sending invitation', 'error');
                }
            }
            
            /**
             * Generate QR code for the room
             */
            async generateQRCode() {
                try {
                    const response = await this.apiCall({
                        action: 'generate_qr_code'
                    });
            
                    if (response && response.success) {
                        $('#qr-code-container').html(`<img src="${response.qr_code_url}" alt="Room QR Code" class="img-fluid" id="qr-code-image">`);
                        $('#qr-modal').addClass('show');
                    } else {
                        this.showNotification('Error generating QR code: ' + (response ? response.error : 'Unknown error'), 'error');
                    }
                } catch (error) {
                    this.showNotification('Error generating QR code', 'error');
                }
            }
            
            /**
             * Close QR code modal
             */
            closeQRModal() {
                $('#qr-modal').removeClass('show');
            }
            
            /**
             * Copy room link to clipboard
             */
            copyRoomLink() {
                const linkInput = document.getElementById('room-link');
                linkInput.select();
                linkInput.setSelectionRange(0, 99999);
            
                try {
                    document.execCommand('copy');
                    this.showNotification('Room link copied to clipboard', 'success');
                } catch (error) {
                    this.showNotification('Failed to copy link', 'error');
                }
            }
            
            /**
             * Download QR code image
             */
            downloadQRCode() {
                const qrImage = document.getElementById('qr-code-image');
                if (qrImage) {
                    const link = document.createElement('a');
                    link.href = qrImage.src;
                    link.download = `room-${this.roomName}-qr-code.png`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    this.showNotification('QR code downloaded', 'success');
                } else {
                    this.showNotification('QR code not available', 'error');
                }
            }
            
            /**
             * Open scan QR code modal
             */
            openScanModal() {
                $('#scan-modal').addClass('show');
                $('#qr-file').val('');
                $('#scan-result').hide();
                $('#scan-preview').hide();
                $('#process-btn').prop('disabled', true);
            }
            
            /**
             * Close scan QR code modal
             */
            closeScanModal() {
                $('#scan-modal').removeClass('show');
            }
            
            /**
             * Handle file selection for QR code scanning
             */
            handleFileSelect(event) {
                const file = event.target.files[0];
                if (file) {
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        $('#preview-image').attr('src', e.target.result);
                        $('#scan-preview').show();
                        $('#process-btn').prop('disabled', false);
                    };
                    reader.readAsDataURL(file);
                }
            }
            
            /**
             * Process uploaded QR code
             */
            async processQRCode() {
                const fileInput = document.getElementById('qr-file');
                const file = fileInput.files[0];
            
                if (!file) {
                    this.showNotification('Please select a QR code image', 'warning');
                    return;
                }
            
                $('#scan-result').show().html(`
                    <div class="alert alert-info">
                        <i class="fas fa-spinner fa-spin"></i> Processing QR code...
                    </div>
                `);
            
                $('#process-btn').prop('disabled', true);
            
                try {
                    // For now, we'll use a simple approach - try to decode using an online service
                    const formData = new FormData();
                    formData.append('file', file);
                    formData.append('action', 'decode_qr');
            
                    const response = await fetch('room.php', {
                        method: 'POST',
                        body: formData
                    });
            
                    const result = await response.json();
            
                    if (result.success && result.qr_data) {
                        const qrData = JSON.parse(result.qr_data);
            
                        if (qrData.action === 'join_room' && qrData.roomname) {
                            // Attempt to join the room
                            await this.joinRoomFromQR(qrData.roomname);
                        } else {
                            $('#scan-result').html(`
                                <div class="alert alert-warning">
                                    <i class="fas fa-exclamation-triangle"></i> Invalid QR code format
                                </div>
                            `);
                        }
                    } else {
                        $('#scan-result').html(`
                            <div class="alert alert-danger">
                                <i class="fas fa-times"></i> Could not decode QR code. Please try a clearer image.
                            </div>
                        `);
                    }
                } catch (error) {
                    console.error('QR processing error:', error);
                    $('#scan-result').html(`
                        <div class="alert alert-danger">
                            <i class="fas fa-times"></i> Error processing QR code
                        </div>
                    `);
                }
            
                $('#process-btn').prop('disabled', false);
            }
            
            /**
             * Join room from QR code data
             */
            async joinRoomFromQR(roomname) {
                try {
                    const response = await this.apiCall({
                        action: 'join_room',
                        roomname: roomname
                    });
            
                    if (response && response.success) {
                        $('#scan-result').html(`
                            <div class="alert alert-success">
                                <i class="fas fa-check"></i> Successfully joined room "${roomname}"!
                            </div>
                        `);
            
                        // Redirect to the room after a short delay
                        setTimeout(() => {
                            window.location.href = `room.php?roomname=${encodeURIComponent(roomname)}`;
                        }, 2000);
                    } else {
                        $('#scan-result').html(`
                            <div class="alert alert-danger">
                                <i class="fas fa-times"></i> Failed to join room: ${response ? response.error : 'Unknown error'}
                            </div>
                        `);
                    }
                } catch (error) {
                    $('#scan-result').html(`
                        <div class="alert alert-danger">
                            <i class="fas fa-times"></i> Error joining room
                        </div>
                    `);
                }
            }

            // ===== ROOM SETTINGS =====

            /**
             * Open room settings modal
             */
            openRoomSettings() {
                $('#room-settings-modal').addClass('show');
            }

            /**
             * Close room settings modal
             */
            closeRoomSettings() {
                $('#room-settings-modal').removeClass('show');
            }

            /**
             * Save room settings
             */
            async saveRoomSettings() {
                try {
                    const formData = new FormData($('#room-settings-form')[0]);
                    const settings = {
                        privacy: formData.get('privacy'),
                        max_members: parseInt(formData.get('max_members')),
                        require_approval: formData.get('require_approval') === 'on',
                        allow_guests: formData.get('allow_guests') === 'on',
                        welcome_message: formData.get('welcome_message')
                    };

                    const response = await this.apiCall({
                        action: 'update_room_settings',
                        settings: JSON.stringify(settings)
                    });

                    if (response && response.success) {
                        this.showNotification('Room settings updated successfully', 'success');
                        this.closeRoomSettings();
                    } else {
                        this.showNotification('Error updating settings: ' + (response ? response.error : 'Unknown error'), 'error');
                    }
                } catch (error) {
                    this.showNotification('Error updating settings', 'error');
                }
            }

            // ===== NOTIFICATION SYSTEM =====

            /**
             * Toggle notifications modal
             */
            toggleNotifications() {
                const modal = $('#notifications-modal');
                if (modal.hasClass('show')) {
                    this.closeNotifications();
                } else {
                    this.openNotifications();
                }
            }

            /**
             * Open notifications modal
             */
            openNotifications() {
                $('#notifications-modal').addClass('show');
                this.loadPendingRequests();
            }

            /**
             * Close notifications modal
             */
            closeNotifications() {
                $('#notifications-modal').removeClass('show');
            }

            /**
             * Update notification badge
             */
            updateNotificationBadge(count) {
                const badge = $('#notification-badge');
                if (count > 0) {
                    badge.text(count).removeClass('hidden');
                } else {
                    badge.addClass('hidden');
                }
            }

            /**
             * Show a notification toast
             */
            showNotification(message, type = 'info') {
                const container = $('#notification-container');
                const notification = $(`
                    <div class="notification ${type}">
                        <div class="icon">
                            ${this.getNotificationIcon(type)}
                        </div>
                        <div class="content">${this.escapeHtml(message)}</div>
                        <button class="close" onclick="$(this).parent().fadeOut(300, function() { $(this).remove(); })">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `);

                container.append(notification);

                // Auto remove after 5 seconds
                setTimeout(() => {
                    notification.fadeOut(300, () => notification.remove());
                }, 5000);
            }

            /**
             * Get notification icon based on type
             */
            getNotificationIcon(type) {
                const icons = {
                    success: '<i class="fas fa-check-circle"></i>',
                    error: '<i class="fas fa-exclamation-circle"></i>',
                    warning: '<i class="fas fa-exclamation-triangle"></i>',
                    info: '<i class="fas fa-info-circle"></i>'
                };
                return icons[type] || icons.info;
            }

            // ===== THEME MANAGEMENT =====

            /**
             * Toggle between light and dark themes
             */
            async toggleTheme() {
                try {
                    const response = await this.apiCall({
                        action: 'toggle_theme'
                    });

                    if (response && response.success) {
                        const isDark = response.dark_mode;
                        const theme = isDark ? 'dark' : 'light';
                        
                        // Update the HTML data-theme attribute
                        document.documentElement.setAttribute('data-theme', theme);
                        
                        // Update the button text and icon
                        const themeBtn = $('#theme-toggle-btn');
                        const icon = themeBtn.find('i');
                        const textSpan = themeBtn.find('span');
                        
                        if (isDark) {
                            icon.removeClass('fa-moon').addClass('fa-sun');
                            textSpan.text('Light');
                        } else {
                            icon.removeClass('fa-sun').addClass('fa-moon');
                            textSpan.text('Dark');
                        }
                    } else {
                        this.fallbackThemeToggle();
                    }
                } catch (error) {
                    this.fallbackThemeToggle();
                }
            }

            /**
             * Fallback theme toggle without API call
             */
            fallbackThemeToggle() {
                const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                
                // Update the HTML data-theme attribute
                document.documentElement.setAttribute('data-theme', newTheme);
                
                // Update the button text and icon
                const themeBtn = $('#theme-toggle-btn');
                const icon = themeBtn.find('i');
                const textSpan = themeBtn.find('span');
                
                if (newTheme === 'dark') {
                    icon.removeClass('fa-moon').addClass('fa-sun');
                    textSpan.text('Light');
                } else {
                    icon.removeClass('fa-sun').addClass('fa-moon');
                    textSpan.text('Dark');
                }
            }

            // ===== SIDEBAR MANAGEMENT =====

            /**
             * Toggle sidebar visibility
             */
            toggleSidebar() {
                $('#sidebar').toggleClass('show');
            }

            // ===== UTILITY FUNCTIONS =====

            /**
             * Scroll to bottom of messages container
             */
            scrollToBottom() {
                const container = $('#messages-container');
                container.scrollTop(container[0].scrollHeight);
            }

            /**
             * Scroll to bottom if near the bottom
             */
            scrollToBottomIfNear() {
                const container = $('#messages-container');
                const threshold = 100;
                const currentScroll = container.scrollTop();
                const maxScroll = container[0].scrollHeight - container.outerHeight();
                
                if (maxScroll - currentScroll <= threshold) {
                    this.scrollToBottom();
                }
            }

            /**
             * Format timestamp for display
             */
            formatTimestamp(timestamp) {
                try {
                    const date = new Date(timestamp);
                    const now = new Date();
                    const diff = now - date;

                    if (diff < 60000) {
                        return 'Just now';
                    } else if (diff < 3600000) {
                        return Math.floor(diff / 60000) + 'm ago';
                    } else if (diff < 86400000) {
                        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    } else {
                        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    }
                } catch (e) {
                    return 'Unknown';
                }
            }

            /**
             * Format relative time
             */
            formatRelativeTime(timestamp) {
                try {
                    const date = new Date(timestamp);
                    const now = new Date();
                    const diff = now - date;

                    const minutes = Math.floor(diff / 60000);
                    const hours = Math.floor(diff / 3600000);
                    const days = Math.floor(diff / 86400000);

                    if (minutes < 1) return 'Just now';
                    if (minutes < 60) return `${minutes}m ago`;
                    if (hours < 24) return `${hours}h ago`;
                    if (days < 7) return `${days}d ago`;
                    return date.toLocaleDateString();
                } catch (e) {
                    return 'Unknown';
                }
            }

            /**
             * Escape HTML to prevent XSS
             */
            escapeHtml(unsafe) {
                if (unsafe === null || unsafe === undefined) return '';
                return unsafe.toString()
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }

            /**
             * Copy message to clipboard
             */
            async copyMessage(text) {
                try {
                    await navigator.clipboard.writeText(text);
                    this.showNotification('Message copied to clipboard', 'success');
                } catch (error) {
                    console.error('Failed to copy message:', error);
                    this.showNotification('Failed to copy message', 'error');
                }
            }

            /**
             * Reply to a message
             */
            replyToMessage(username, message) {
                const input = $('#message-input');
                const replyText = `@${username} `;
                input.val(replyText + input.val()).focus();
                this.updateCharCount();
            }

            // ===== EVENT HANDLERS =====

            /**
             * Handle page unload
             */
            handlePageUnload() {
                // Send beacon to update offline status
                const data = new URLSearchParams({
                    action: 'ping',
                    username: this.username,
                    roomname: this.roomName
                });
                navigator.sendBeacon('room.php', data);
            }

            /**
             * Handle window focus
             */
            handleWindowFocus() {
                // Mark as active when window gains focus
                this.sendPing();
            }

            /**
             * Handle visibility change
             */
            handleVisibilityChange() {
                if (document.visibilityState === 'visible') {
                    this.handleWindowFocus();
                }
            }

            /**
             * Handle keyboard shortcuts
             */
            handleKeyboardShortcuts(e) {
                // Ctrl/Cmd + K to focus message input
                if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                    e.preventDefault();
                    $('#message-input').focus();
                }
                
                // Escape to close modals
                if (e.key === 'Escape') {
                    this.closeRoomSettings();
                    this.closeNotifications();
                    this.closeInviteModal();
                }
            }

            /**
             * Send ping to keep session alive
             */
            async sendPing() {
                try {
                    await this.apiCall({
                        action: 'ping'
                    });
                } catch (error) {
                    console.error('Ping failed:', error);
                }
            }

/**
 * Leave the room via AJAX
 */
async leaveRoom() {
    if (!confirm('Are you sure you want to leave this room?')) {
        return;
    }

    try {
        const response = await this.apiCall({
            action: 'leave_room'
        });

        if (response && response.success) {
            this.showNotification('You have left the room', 'success');
            
            // Redirect to index after a short delay
            setTimeout(() => {
                window.location.href = 'index.php';
            }, 1000);
        } else {
            this.showNotification('Failed to leave room: ' + (response.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error leaving room:', error);
        this.showNotification('Error leaving room', 'error');
    }
}

            /**
             * Clean up resources
             */
            destroy() {
                this.clearIntervals();
                console.log('Chat app destroyed');
            }
        }

        // Global functions for HTML onclick handlers
        function openRoomSettings() {
            if (window.chatApp) {
                window.chatApp.openRoomSettings();
            }
        }

        function closeRoomSettings() {
            if (window.chatApp) {
                window.chatApp.closeRoomSettings();
            }
        }

        function toggleNotifications() {
            if (window.chatApp) {
                window.chatApp.toggleNotifications();
            }
        }

        function closeNotifications() {
            if (window.chatApp) {
                window.chatApp.closeNotifications();
            }
        }

        function toggleTheme() {
            if (window.chatApp) {
                window.chatApp.toggleTheme();
            }
        }

        function toggleSidebar() {
            if (window.chatApp) {
                window.chatApp.toggleSidebar();
            }
        }

        function leaveRoom() {
            if (window.chatApp) {
                window.chatApp.leaveRoom();
            }
        }

        function approveRequest(requestId) {
            if (window.chatApp) {
                window.chatApp.approveRequest(requestId);
            }
        }

        function denyRequest(requestId) {
            if (window.chatApp) {
                window.chatApp.denyRequest(requestId);
            }
        }

        function sendInvitation() {
            if (window.chatApp) {
                window.chatApp.sendInvitation();
            }
        }

        function saveRoomSettings() {
            if (window.chatApp) {
                window.chatApp.saveRoomSettings();
            }
        }

        // Initialize the chat app when DOM is ready
        $(document).ready(() => {
            window.chatApp = new ChatApp();
        });

        // Clean up on page unload
        $(window).on('beforeunload', () => {
            if (window.chatApp) {
                window.chatApp.destroy();
            }
        });

        function openInviteModal() {
            if (window.chatApp) {
                window.chatApp.openInviteModal();
            }
        }

        function closeInviteModal() {
            if (window.chatApp) {
                window.chatApp.closeInviteModal();
            }
        }
        
        function generateQRCode() {
            if (window.chatApp) {
                window.chatApp.generateQRCode();
            }
        }
        
        function closeQRModal() {
            if (window.chatApp) {
                window.chatApp.closeQRModal();
            }
        }
        
        function openScanModal() {
            if (window.chatApp) {
                window.chatApp.openScanModal();
            }
        }
        
        function closeScanModal() {
            if (window.chatApp) {
                window.chatApp.closeScanModal();
            }
        }
        
        function handleFileSelect(event) {
            if (window.chatApp) {
                window.chatApp.handleFileSelect(event);
            }
        }
        
        function processQRCode() {
            if (window.chatApp) {
                window.chatApp.processQRCode();
            }
        }
    </script>
</body>
</html>

<?php
// Close database connection and clean up
if (isset($conn)) {
    $conn->close();
}

// Clear any sensitive data from memory
unset($validator, $security, $roomManager);
?>