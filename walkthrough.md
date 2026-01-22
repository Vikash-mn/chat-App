# Walkthrough: Fixes for Admin Login and Signup

## Overview
This walkthrough details the fixes applied to `admin.php` and `signup.php` to resolve session errors and SQL query failures.

## Fixes Applied

### 1. Admin Session Consistency (`admin.php`)
**Issue:** A PHP Warning `Undefined array key "login_time"` occurred because the session state could be inconsistent (logged in but missing `login_time`).
**Fix:** Added a session consistency check at the beginning of `admin.php`.
```php
if (isset($_SESSION['admin_logged_in']) && !isset($_SESSION['login_time'])) {
    unset($_SESSION['admin_logged_in'], $_SESSION['admin_username']);
    header("Location: admin.php");
    exit();
}
```
**Result:** Inconsistent sessions now trigger a clean logout instead of an error.

### 2. Signup SQL Error (`signup.php`)
**Issue:** A fatal error occurred during signup because the code tried to select the `id` column from the `users` table, but the table uses `username` as the primary key and has no `id` column.
**Fix:** Changed the user existence check query to select `username` instead of `id`.
```php
// Before
$query = "SELECT id FROM users WHERE username = ? OR email = ?";

// After
$query = "SELECT username FROM users WHERE username = ? OR email = ?";
```
**Result:** Signup now correctly checks for existing users without crashing.

### 3. Signup Validation Restoration (`signup.php`)
**Issue:** During the fix, some validation logic (email, password length) was accidentally removed.
**Fix:** Restored the missing validation blocks to ensure data integrity and security.

## Verification
- **Database Schema:** Verified `db_setup.php` confirms `users` table has `username` as PK and no `id` column.
- **Consistency:** Checked `login.php`, `profile.php`, `room.php`, and `index.php` to ensure they all correctly use `username` for user identification.
- **Code Quality:** Verified `signup.php` syntax and logic flow.

## Next Steps
The application core flows (Signup -> Login -> Admin/Chat) should now be stable.
