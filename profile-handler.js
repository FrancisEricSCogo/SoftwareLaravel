// Function to safely update profile image
function updateProfileImage(profilePic) {
    const avatarEl = document.getElementById('avatar');
    if (!avatarEl) return;

    const baseUrl = window.getBase();
    const defaultImageUrl = new URL('uploads/default-profile.png', baseUrl).toString();
    
    if (!profilePic) {
        avatarEl.src = defaultImageUrl;
        return;
    }

    // Handle profile picture path - backend returns /uploads/... or uploads/...
    let profilePicPath = profilePic;
    // If it doesn't start with http or /, add / prefix
    if (!profilePicPath.startsWith('http') && !profilePicPath.startsWith('/')) {
      profilePicPath = '/' + profilePicPath;
    }
    // If it starts with uploads/, add / prefix
    if (profilePicPath.startsWith('uploads/')) {
      profilePicPath = '/' + profilePicPath;
    }

    const imageUrl = new URL(profilePicPath.replace(/^\//, ''), baseUrl).toString();
    avatarEl.src = imageUrl;
    avatarEl.onerror = () => {
        avatarEl.onerror = null;
        avatarEl.src = defaultImageUrl;
    };
}

// Function to safely update profile fields
function updateProfileFields(userData) {
    const fields = {
        name: document.getElementById('name'),
        username: document.getElementById('username'),
        email: document.getElementById('email'),
        contact_number: document.getElementById('contact_number')
    };

    Object.entries(fields).forEach(([key, element]) => {
        if (element && userData[key]) {
            element.value = userData[key];
        }
    });

    // Update profile image
    updateProfileImage(userData.profilePic);
}

// Export functions if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        updateProfileImage,
        updateProfileFields
    };
}