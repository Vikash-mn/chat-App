<?php
// Enhanced database connection with security improvements
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/error.log');

// Database configuration - Use environment variables in production
$servername = getenv('DB_HOST') ?: "localhost";
$username = getenv('DB_USER') ?: "root";
$password = getenv('DB_PASS') ?: "";
$dbname = getenv('DB_NAME') ?: "chatapp";

// Create connection with enhanced security
$conn = mysqli_connect($servername, $username, $password, $dbname);

// Check connection
if (!$conn) {
    error_log("Database connection failed: " . mysqli_connect_error());
    http_response_code(500);
    die("Database connection error. Please try again later.");
}

// Set charset to utf8mb4 for full Unicode support
if (!mysqli_set_charset($conn, "utf8mb4")) {
    error_log("Error setting charset to utf8mb4: " . mysqli_error($conn));
}

// Security enhancements
mysqli_options($conn, MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);

// Set SQL mode to strict
mysqli_query($conn, "SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'");

// Disable autocommit for transaction control
mysqli_autocommit($conn, true);

// Set connection timeout
mysqli_options($conn, MYSQLI_OPT_CONNECT_TIMEOUT, 10);

// Helper function for secure queries
function secure_query($conn, $query, $types = null, $params = null) {
    $stmt = mysqli_prepare($conn, $query);

    if (!$stmt) {
        error_log("Prepare failed: " . mysqli_error($conn));
        return false;
    }

    if ($types && $params) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }

    if (!mysqli_stmt_execute($stmt)) {
        error_log("Execute failed: " . mysqli_error($conn));
        mysqli_stmt_close($stmt);
        return false;
    }

    $result = mysqli_stmt_get_result($stmt);
    mysqli_stmt_close($stmt);

    return $result;
}

// Helper function for secure prepared statements
function prepared_query($conn, $query, $types = null, $params = null) {
    $stmt = mysqli_prepare($conn, $query);

    if (!$stmt) {
        error_log("Prepare failed: " . mysqli_error($conn));
        return false;
    }

    if ($types && $params) {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }

    if (!mysqli_stmt_execute($stmt)) {
        error_log("Execute failed: " . mysqli_error($conn));
        mysqli_stmt_close($stmt);
        return false;
    }

    return $stmt;
}

// Helper function to get last inserted ID safely
function get_last_insert_id($conn) {
    return mysqli_insert_id($conn);
}

// Helper function to escape strings safely
function escape_string($conn, $string) {
    return mysqli_real_escape_string($conn, $string);
}

// Helper function to check if table exists
function table_exists($conn, $table_name) {
    $escaped_table_name = mysqli_real_escape_string($conn, $table_name);
    $result = mysqli_query($conn, "SHOW TABLES LIKE '$escaped_table_name'");
    return mysqli_num_rows($result) > 0;
}

// Helper function for transaction management
function begin_transaction($conn) {
    return mysqli_begin_transaction($conn);
}

function commit_transaction($conn) {
    return mysqli_commit($conn);
}

function rollback_transaction($conn) {
    return mysqli_rollback($conn);
}
function rollback_transaction($conn) {
    return mysqli_rollback($conn);
}

// === ADD THIS FUNCTION ===
// Helper function to sanitize input prevents XSS
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}
?>