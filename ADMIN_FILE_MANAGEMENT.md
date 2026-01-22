# Admin File Management Guide

## Overview
The Galaxy Chat admin portal now includes comprehensive file management capabilities that allow administrators to view, download, and manage all files uploaded across all rooms.

## Accessing File Management

### 1. Login to Admin Portal
```
URL: http://localhost/chart/admin.php
Password: 2676
```

### 2. Navigate to Files Tab
- Click on the **"Files"** tab in the admin navigation
- This will display the File Management interface

## Features

### 📁 File Overview
- **Total Files Count**: Shows the total number of files in the system
- **Total Size**: Displays the combined size of all files
- **File Statistics by Room**: Breakdown of files per room with size information

### 📋 File List Table
The main file table displays:
- **Filename**: Clickable link to download/view the file
- **Room**: Which room the file belongs to
- **Uploaded By**: Username of the person who uploaded the file
- **Size**: File size in KB
- **Upload Date**: When the file was uploaded
- **Actions**: Delete button for each file

### 🗑️ File Deletion
- Click the **"Delete"** button next to any file
- Confirm the deletion in the popup dialog
- The system will:
  - Delete the physical file from the server
  - Remove the database record
  - Show a success message

### 📊 File Statistics
- **Room-wise breakdown**: See how many files are in each room
- **Size per room**: Total size of files in each room
- **Visual cards**: Easy-to-read statistics display

## Security Features

### 🔐 Access Control
- Only logged-in administrators can access file management
- Files are served with proper security headers
- Room-specific access tokens are validated

### 🛡️ File Validation
- Files are validated during upload
- Size limits are enforced (5MB max)
- File type restrictions apply

## Troubleshooting

### Common Issues

#### Files Not Showing
- Check if files exist in the database: `SELECT * FROM files;`
- Verify file paths are correct
- Check server permissions on uploads folder

#### Delete Button Not Working
- Ensure admin session is active
- Check JavaScript console for errors
- Verify database connection

#### Large File Sizes
- Files over 5MB are rejected during upload
- Consider implementing file compression for large files

## Database Structure

### Files Table
```sql
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    roomname VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    filepath VARCHAR(500) NOT NULL,
    filesize INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Key Fields
- `roomname`: Links files to specific rooms
- `username`: Tracks who uploaded the file
- `filepath`: Server path to the physical file
- `filesize`: Size in bytes for calculations

## API Endpoints

### File Upload
```
POST /uploadfile.php
Parameters: roomname, username, file_upload
```

### File Fetch (per room)
```
GET /fetchfiles.php?roomname=ROOM_NAME
```

### File Download
```
GET /uploads/FILENAME
```

## Best Practices

### 🗂️ File Organization
- Files are automatically organized by room
- Physical files stored in `/uploads/` directory
- Database tracks all file metadata

### 🔄 Regular Maintenance
- Periodically check for orphaned files
- Clean up old/unused files
- Monitor disk space usage

### 📈 Monitoring
- Use the admin statistics to monitor file usage
- Set up alerts for large file uploads
- Track file type distributions

## Quick Actions

### View All Files
```bash
http://localhost/chart/admin.php?tab=files
```

### Check File Issues
```bash
http://localhost/chart/fix_file_rooms.php
```

### Test File Filtering
```bash
http://localhost/chart/test_file_filtering.php
```

## Support

If you encounter issues with file management:
1. Check the browser console for JavaScript errors
2. Verify database connectivity
3. Check server error logs
4. Use the diagnostic tools provided

---

**Admin Password**: 2676
**File Size Limit**: 5MB per file
**Supported Operations**: View, Download, Delete