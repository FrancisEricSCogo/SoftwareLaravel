// frontend/app.js - Updated to use Axios
if (!window.BASE) {
  // Fixed backend URL - disable auto-detection to prevent refresh issues
  window.BASE = 'http://127.0.0.1:8000/';
  localStorage.setItem('BACKEND_BASE', window.BASE);
}

// Initialize Axios when it's available
function initializeAxios() {
  if (typeof axios !== 'undefined') {
    // Set Axios defaults
    axios.defaults.baseURL = window.BASE + 'api/';
    axios.defaults.timeout = 10000;
    axios.defaults.withCredentials = true;
    
    // Add request interceptor for token
    axios.interceptors.request.use(
      (config) => {
        const token = getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Add response interceptor for error handling
    axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401 || error.response?.status === 403) {
          clearToken();
          setAuthUI(false);
          if (!location.pathname.endsWith('login.html')) {
            location.href = 'login.html';
          }
        }
        return Promise.reject(error);
      }
    );
    
    console.log('Axios initialized successfully');
  } else {
    // Retry after a short delay if axios is not yet loaded
    setTimeout(initializeAxios, 100);
  }
}

// Start initialization
initializeAxios();

function setBase(url) {
  if (!url) return;
  if (/^:?\d+$/.test(String(url))) url = `http://localhost:${String(url).replace(/^:/, '')}/`;
  if (!/^https?:\/\//.test(url)) url = 'http://' + url;
  if (!url.endsWith('/')) url += '/';
  window.BASE = url;
  localStorage.setItem('BACKEND_BASE', url);
}

function getBase() {
  return window.BASE;
}

window.setBase = setBase;
window.getBase = getBase;

// DISABLED: Backend auto-detection to prevent refresh issues
// The backend URL is now fixed to http://127.0.0.1:8000/

// Token management
function saveToken(token) { 
  if (token) localStorage.setItem('token', token); 
  else localStorage.removeItem('token');
}

function getToken() { 
  return localStorage.getItem('token'); 
}

function clearToken() { 
  localStorage.removeItem('token'); 
}

function isAuthed() { 
  return !!getToken(); 
}

function setAuthUI(isLoggedIn) {
  document.querySelectorAll('.guest-only').forEach(el => el.style.display = isLoggedIn ? 'none' : '');
  document.querySelectorAll('.auth-only').forEach(el => el.style.display = isLoggedIn ? '' : 'none');
}

async function requireAuth(redirectTo = 'login.html') {
  try {
    if (!isAuthed()) throw new Error('no token');
    await api('/users/me');
    setAuthUI(true);
    return true;
  } catch (err) {
    // Only clear token and redirect if 401/403 or token-related error
    if (err && (err.response?.status === 401 || err.response?.status === 403 || (err.message && /token|auth/i.test(err.message)))) {
      clearToken();
      setAuthUI(false);
      if (!location.pathname.endsWith(redirectTo)) location.href = redirectTo;
    }
    return false;
  }
}

function checkAuthStatus() {
  if (!isAuthed()) {
    setAuthUI(false);
    return;
  }
  api('/users/me')
    .then(me => {
      // Backend returns plain user object; normalize if wrapped
      const user = me && me.data ? me.data : me;
      window.currentUser = user;
      setAuthUI(true);
      document.querySelectorAll('.user-name').forEach(el => { try { el.textContent = user.name } catch(e){} });
    })
    .catch(() => {
      clearToken();
      setAuthUI(false);
    });
}

// API wrapper using Axios
async function api(path, { method = 'GET', data, multipart } = {}) {
  const config = {
    method: method.toLowerCase(),
    url: path.startsWith('/') ? path.substring(1) : path,
  };

  if (multipart) {
    config.data = data;
    config.headers = {
      'Content-Type': 'multipart/form-data'
    };
  } else if (data) {
    config.data = data;
    config.headers = {
      'Content-Type': 'application/json'
    };
  }

  try {
    const response = await axios(config);
    return response.data;
  } catch (error) {
    // Re-throw with consistent error format
    const errorResponse = {
      message: error.response?.data?.message || error.message || 'Request failed',
      status: error.response?.status,
      errors: error.response?.data?.errors,
      ...error.response?.data
    };
    throw errorResponse;
  }
}

// DISABLED: Automatic auth check to prevent refresh issues
// setAuthUI(isAuthed());

if (!window.showAlert) {
  window.showAlert = (title, text, icon) => {
    if (window.Swal && typeof Swal.fire === 'function') {
      return Swal.fire({ title, text, icon, confirmButtonText: 'OK' });
    }
    alert(`${title}: ${text}`);
    return Promise.resolve();
  };
}
var showAlert = window.showAlert;

// ==================
// Global: Logout btn
// ==================
const logoutBtn = document.getElementById('btnLogout');
if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try {
      await api('/auth/logout', { method: 'POST' });
    } catch (err) {
      // Ignore errors, always clear token
    }
    clearToken();
    showAlert('Logged Out', 'You have successfully logged out.', 'success');
    location.href = 'login.html';
  });
}

// ======================
// Register page logic
// ======================
const registerForm = document.getElementById('registerForm');
if (registerForm) {
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(registerForm);
    const data = {
      name: formData.get('name'),
      username: formData.get('username'),
      email: formData.get('email'),
      password: formData.get('password'),
      contact_number: formData.get('contact_number')
    };
    try {
      const res = await api('/auth/register', { method: 'POST', data: data });
      const email = res?.email || formData.get('email') || document.getElementById('registerEmail')?.value;
      const message = res?.message || 'User created. Please check your email for verification.';
      await showAlert('Registration Successful', message, 'success');
      const regLoading = document.getElementById('registerLoading');
      if (regLoading) regLoading.textContent = 'User created. Redirecting to verification...';
      registerForm.reset();
      setTimeout(() => location.href = `verify-email.html?email=${encodeURIComponent(email || '')}`, 700);
    } catch (err) {
      console.log('Registration error:', err);
      let errorMessage = 'Registration failed. Please try again.';
      
      // Handle Laravel validation errors format
      if (err?.errors && typeof err.errors === 'object') {
        // Laravel returns errors as { field: [messages] }
        const errorMessages = [];
        for (const field in err.errors) {
          if (Array.isArray(err.errors[field])) {
            errorMessages.push(...err.errors[field]);
          } else {
            errorMessages.push(err.errors[field]);
          }
        }
        if (errorMessages.length > 0) {
          errorMessage = errorMessages.join('. ');
        }
      } else if (err?.errors && Array.isArray(err.errors) && err.errors.length > 0) {
        // Handle array format errors
        errorMessage = err.errors[0].msg || err.errors[0] || errorMessage;
      } else if (err?.message) {
        errorMessage = err.message;
      } else if (typeof err === 'string') {
        errorMessage = err;
      }
      
      await showAlert('Registration Failed', errorMessage, 'error');
      const loadingEl = document.getElementById('registerLoading');
      if (loadingEl) loadingEl.textContent = errorMessage;
    }
  });
}

// ================
// Login page logic
// ================
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      username: loginForm.username.value,
      password: loginForm.password.value,
    };
    try {
      const res = await api('/auth/login', { method: 'POST', data: payload });
      // Accept either {token, user} or {access_token, user}
      const token = res.token || res.access_token;
      if (!token) throw { message: 'No token returned from server.' };
      saveToken(token);
      showAlert('Welcome', 'Welcome, ' + (res.user?.name || 'User'), 'success');
      const loginLoadingEl = document.getElementById('loginLoading');
      if (loginLoadingEl) loginLoadingEl.textContent = 'Welcome, ' + (res.user?.name || 'User');
      setTimeout(() => location.href = 'software.html', 600);
    } catch (err) {
      console.log('Login error:', err);
      const errorMsg = err.error || err.message || '';
      if (errorMsg.includes('not verified')) {
        let email = err.email || '';
        if (!email) {
          const { value: userEmail } = await Swal.fire({
            title: 'Email Verification Required',
            text: 'Please enter your email address to proceed with verification.',
            input: 'email',
            inputPlaceholder: 'Enter your email',
            inputValidator: (value) => {
              if (!value) return 'Email is required!';
            },
            showCancelButton: true,
            confirmButtonText: 'Continue',
            cancelButtonText: 'Cancel'
          });
          if (userEmail) {
            email = userEmail;
          } else {
            showAlert('Login Failed', 'Email verification is required to login.', 'error');
            const loginLoadingEl2 = document.getElementById('loginLoading');
            if (loginLoadingEl2) loginLoadingEl2.textContent = 'Login failed';
            return;
          }
        }
        console.log('Redirecting with email:', email);
        // Attempt to resend OTP so the user receives a fresh code
        try {
          await api('/auth/resend-otp', { method: 'POST', data: { email } });
        } catch (e) {
          // Non-fatal; user may already have a valid code
          console.warn('Resend OTP failed:', e);
        }
        const loginLoadingEl4 = document.getElementById('loginLoading');
        if (loginLoadingEl4) loginLoadingEl4.textContent = 'Redirecting to email verification...';
        setTimeout(() => location.href = `verify-email.html?email=${encodeURIComponent(email)}` , 600);
      } else {
        showAlert('Login Failed', errorMsg || 'Unknown error', 'error');
        const loginLoadingEl3 = document.getElementById('loginLoading');
        if (loginLoadingEl3) loginLoadingEl3.textContent = errorMsg || 'Login failed';
      }
    }
  });
}

// Forgot password
const forgotForm = document.getElementById('forgotForm');
if (forgotForm) {
  forgotForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = (forgotForm.email?.value || '').trim();
    if (!email) {
      showAlert('Error', 'Please enter your email address.', 'error');
      return;
    }
    try {
      await api('/auth/forgot-password', { method: 'POST', data: { email } });
      showAlert('Email Sent', 'Password reset instructions have been sent to your email.', 'success');
      forgotForm.reset();
    } catch (err) {
      const msg = err?.message || JSON.stringify(err, null, 2);
      showAlert('Request Failed', msg, 'error');
    }
  });
}

// Reset password
const resetForm = document.getElementById('resetForm');
if (resetForm) {
  resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = resetForm.password?.value || '';
    const confirm = resetForm.confirm_password?.value || '';
    if (!password) {
      await showAlert('Error', 'Please enter a new password.', 'error');
      return;
    }
    if (password !== confirm) {
      await showAlert('Error', 'Passwords do not match.', 'error');
      return;
    }

    const params = new URLSearchParams(location.search);
    const token = params.get('token');
    const payload = token ? { token, password } : { password };

    try {
      const res = await api('/auth/reset-password', { method: 'POST', data: payload });
      const message = (res && (res.message || res.msg)) || 'Password has been reset. You may now log in.';
      await showAlert('Success', message, 'success');
      resetForm.reset();
      setTimeout(() => location.href = 'login.html', 800);
    } catch (err) {
      const msg = (err && (err.message || err.msg || JSON.stringify(err))) || 'Unable to reset password.';
      await showAlert('Reset Failed', msg, 'error');
    }
  });
}

// Home page status
const statusDiv = document.getElementById('status');
if (statusDiv) {
  api('/users/me')
    .then(me => { statusDiv.textContent = `Logged in as ${me.name} (@${me.username})`; })
    .catch(() => { statusDiv.textContent = 'Not logged in'; });
}

// =================
// Profile page logic
// =================
const infoForm = document.getElementById('infoForm');
const photoForm = document.getElementById('photoForm');

async function loadProfile() {
  try {
    const response = await api('/users/me');
    const me = response && response.data ? response.data : response;

    if (document.getElementById('name')) document.getElementById('name').value = me.name || '';
    if (document.getElementById('username')) document.getElementById('username').value = me.username || '';
    if (document.getElementById('email')) document.getElementById('email').value = me.email || '';
    if (document.getElementById('contact_number')) document.getElementById('contact_number').value = me.contact_number || '';

    // Make email visible but not editable / not submitted
    const emailEl = document.getElementById('email');
    if (emailEl) {
      // Show email but prevent user edits
      emailEl.readOnly = true;
      emailEl.setAttribute('aria-readonly', 'true');
      // Remove name attribute so it won't be included if someone uses FormData later
      try { emailEl.removeAttribute('name'); } catch (e) {}
    }
    // If the page has a dedicated display element for email, update it too
    const emailDisplay = document.getElementById('emailDisplay');
    if (emailDisplay) emailDisplay.textContent = me.email || '';

    // Handle profile picture - backend returns /uploads/... or uploads/...
    let profilePicUrl = me.profilePic || '/uploads/default-profile.png';
    // If it doesn't start with http or /, add / prefix
    if (!profilePicUrl.startsWith('http') && !profilePicUrl.startsWith('/')) {
      profilePicUrl = '/' + profilePicUrl;
    }
    // If it starts with uploads/, add / prefix
    if (profilePicUrl.startsWith('uploads/')) {
      profilePicUrl = '/' + profilePicUrl;
    }
    
    const fullUrl = new URL(profilePicUrl.replace(/^\//, ''), getBase()).toString();
    const img = document.getElementById('avatar');
    const fallbackProfile = new URL('uploads/default-profile.png', getBase()).toString();
    if (img) {
      img.src = fullUrl;
      img.onerror = () => { 
        img.onerror = null; 
        img.src = fallbackProfile; 
      };
    }
  } catch (err) {
    showAlert('Error', 'Failed to load profile: ' + (err.message || 'Unknown error'), 'error');
    const box = document.getElementById('profileMsg');
    if (box) box.textContent = 'Failed to load profile';
  }
}

if (infoForm) {
  loadProfile();
  
  infoForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      name: document.getElementById('name').value.trim(),
      username: document.getElementById('username').value.trim(),
      contact_number: document.getElementById('contact_number').value.trim(),
      keep_profile_image: true
    };

    // Safety: ensure email is never sent/updated from this form
    if ('email' in payload) delete payload.email;

    try {
      await api('/users/me', { method: 'PUT', data: payload });
      showAlert('Success', 'Profile updated successfully!', 'success');
      loadProfile();
    } catch (err) {
      showAlert('Error', 'Failed to update profile: ' + (err.message || 'Unknown error'), 'error');
      document.getElementById('profileMsg').textContent = err.message || 'Update failed';
    }
  });
}

if (photoForm) {
  photoForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(photoForm);
    try {
      const { profilePic } = await api('/users/me/photo', { method: 'PUT', data: fd, multipart: true });
      const fullUrl = new URL(String(profilePic || '').replace(/^\//, ''), getBase()).toString();
      const avatar = document.getElementById('avatar');
      if (avatar) {
        avatar.src = `${fullUrl}?t=${Date.now()}`;
      }
      showAlert('Success', 'Profile photo updated successfully!', 'success');
      photoForm.reset();
    } catch (err) {
      showAlert('Error', 'Failed to update profile photo: ' + (err.message || 'Unknown error'), 'error');
    }
  });
}

// Change password
const passwordForm = document.getElementById('passwordForm');
if (passwordForm) {
  passwordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(passwordForm);
    const payload = Object.fromEntries(fd.entries());
    const box = document.getElementById('profileMsg');

    try {
      const res = await api('/users/me/password', { method: 'PUT', data: payload });
      const message = (res && (res.message || res.msg)) || 'Password changed. Please log in again.';
      if (box) box.textContent = message;
      await showAlert('Success', message, 'success');
      clearToken();
      location.href = 'login.html';
    } catch (err) {
      const errMsg = err?.message || JSON.stringify(err, null, 2);
      if (box) box.textContent = errMsg;
      await showAlert('Error', errMsg, 'error');
    }
  });
}

// ====================================
// Software list page (create/list/delete)
// ====================================
const addForm = document.getElementById('addForm');
const tblBody = document.querySelector('#tbl tbody');
const msg = document.getElementById('softwareMsg');
const search = document.getElementById('search');

function renderRow(row) {
  // Handle software image path - backend returns /uploads/... or uploads/...
  let imagePath = row.image_path || '/uploads/software.png';
  // If it doesn't start with http or /, add / prefix
  if (!imagePath.startsWith('http') && !imagePath.startsWith('/')) {
    imagePath = '/' + imagePath;
  }
  // If it starts with uploads/, add / prefix
  if (imagePath.startsWith('uploads/')) {
    imagePath = '/' + imagePath;
  }
  
  const imgUrl = new URL(imagePath.replace(/^\//, ''), getBase()).toString();
  const fallbackUrl = new URL('uploads/software.png', getBase()).toString();

  const tr = document.createElement('tr');
  
  tr.innerHTML = `
    <td>${row.id}</td>
    <td>${escapeHtml(row.vendor)}</td>
    <td>${escapeHtml(row.name)}</td>
    <td>${escapeHtml(row.plan_type)}</td>
    <td>
      <img src="${imgUrl}" alt="${escapeHtml(row.name)}" class="software-image" onerror="this.onerror=null; this.src='${fallbackUrl}'">
    </td>
    <td>
      <button data-action="edit" data-id="${row.id}" class="action-btn">Edit</button>
      <button data-action="delete" data-id="${row.id}" class="action-btn delete-btn">Delete</button>
    </td>
  `;

  tblBody.appendChild(tr);
}

async function loadSoftware(q = '') {
  try {
    const rows = await api('/software' + (q ? `?q=${encodeURIComponent(q)}` : ''));
    if (tblBody) {
      tblBody.innerHTML = '';
      rows.forEach(renderRow);
    }
  } catch (e) {
    if (msg) msg.textContent = 'Please login first.';
    showAlert('Load Failed', 'Failed to load software. Please login or try again.', 'error');
  }
}

if (addForm && tblBody) {

  tblBody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    const id = btn.dataset.id;

    if (btn.dataset.action === 'edit') {
      location.href = `edit.html?id=${encodeURIComponent(id)}`;
      return;
    }

    if (btn.dataset.action === 'delete') {
      Swal.fire({
        title: 'Are you sure?',
        text: "You won't be able to revert this!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, delete it!'
      }).then(async (result) => {
        if (result.isConfirmed) {
          try {
            await api('/software/' + id, { method: 'DELETE' });
            Swal.fire('Deleted!', 'Software has been deleted.', 'success');
            loadSoftware(search?.value || '');
          } catch (err) {
            Swal.fire('Error', 'Failed to delete software: ' + JSON.stringify(err, null, 2), 'error');
            if (msg) msg.textContent = JSON.stringify(err, null, 2);
          }
        }
      });
      return;
    }
  });

  if (search) search.addEventListener('input', () => loadSoftware(search.value));
  loadSoftware();
}

// =====================
// Edit page (edit.html)
// =====================
async function initEdit() {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  if (!id) return;

  const form = document.getElementById('editForm');
  const msgBox = document.getElementById('editMsg');
  const preview = document.getElementById('preview');

  try {
    const response = await api('/software/' + id);
    // API returns {data: item} format
    const software = response.data || response;
    for (const [key, value] of Object.entries(software)) {
      const input = form.elements[key];
      if (input) input.value = value;
    }

    if (preview) {
      // Handle software image path - backend returns /uploads/... or uploads/...
      let imagePath = software.image_path || '/uploads/software.png';
      // If it doesn't start with http or /, add / prefix
      if (!imagePath.startsWith('http') && !imagePath.startsWith('/')) {
        imagePath = '/' + imagePath;
      }
      // If it starts with uploads/, add / prefix
      if (imagePath.startsWith('uploads/')) {
        imagePath = '/' + imagePath;
      }
      const imgUrl = new URL(imagePath.replace(/^\//, ''), getBase()).toString();
      preview.src = imgUrl;
      preview.onerror = function() {
        this.onerror = null;
        this.src = new URL('uploads/software.png', getBase()).toString();
      };
    }
  } catch (err) {
    showAlert('Error', 'Failed to load software details', 'error');
    return;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);

    const fileInput = form.querySelector('input[type="file"]');
    if (fileInput && fileInput.files.length === 0) {
      fd.append('keepImage', '1');
    }

    try {
      await api('/software/' + id, { method: 'PUT', data: fd, multipart: true });
      showAlert('Success', 'Software updated successfully!', 'success');
      setTimeout(() => {
        window.location.href = 'software.html';
      }, 1000);
    } catch (err) {
      showAlert('Error', 'Failed to update software: ' + (err.message || 'Unknown error'), 'error');
    }
  });

  const fileInput = form.querySelector('input[type="file"]');
  if (fileInput && preview) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files?.[0];
      if (file) {
        preview.src = URL.createObjectURL(file);
      } else {
        preview.src = new URL('uploads/software.png', getBase()).toString();
      }
    });
  }
}

// Mobile menu toggle
function toggleMobileMenu() {
  const mobileMenu = document.getElementById('mobileMenu');
  if (mobileMenu) {
    mobileMenu.classList.toggle('hidden');
  }
}
window.toggleMobileMenu = toggleMobileMenu;

// ======================
// Role-based API Functions
// ======================

// Admin Functions
window.adminAPI = {
  // Get all vendors
  async getVendors() {
    return await api('/admin/vendors');
  },
  
  // Approve/reject vendor
  async approveVendor(vendorId, approved) {
    return await api(`/admin/vendors/${vendorId}/approve`, {
      method: 'PUT',
      data: { approved }
    });
  },
  
  // Get all software (admin view)
  async getSoftware() {
    return await api('/admin/software');
  },
  
  // Get all subscriptions (admin view)
  async getSubscriptions() {
    return await api('/admin/subscriptions');
  },
  
  // Manage user status
  async manageUserStatus(userId, isActive) {
    return await api(`/admin/users/${userId}/status`, {
      method: 'PUT',
      data: { is_active: isActive }
    });
  }
};

// Vendor Functions
window.vendorAPI = {
  // Add software
  async addSoftware(formData) {
    return await api('/vendor/software', {
      method: 'POST',
      data: formData,
      multipart: true
    });
  },
  
  // Get vendor's software
  async getSoftware() {
    return await api('/vendor/software');
  },
  
  // Update software
  async updateSoftware(softwareId, formData) {
    return await api(`/vendor/software/${softwareId}`, {
      method: 'PUT',
      data: formData,
      multipart: true
    });
  },
  
  // Delete software
  async deleteSoftware(softwareId) {
    return await api(`/vendor/software/${softwareId}`, {
      method: 'DELETE'
    });
  },
  
  // Get subscriptions for vendor's software
  async getSubscriptions() {
    return await api('/vendor/subscriptions');
  }
};

// Customer Functions
window.customerAPI = {
  // Browse software (public)
  async browseSoftware() {
    return await api('/software');
  },
  
  // View software details
  async viewSoftware(softwareId) {
    return await api(`/software/${softwareId}`);
  },
  
  // Subscribe to software
  async subscribe(softwareId) {
    return await api('/subscribe', {
      method: 'POST',
      data: { software_id: softwareId }
    });
  },
  
  // Get my subscriptions
  async getMySubscriptions() {
    return await api('/my-subscriptions');
  },
  
  // Cancel subscription
  async cancelSubscription(subscriptionId) {
    return await api(`/subscriptions/${subscriptionId}/cancel`, {
      method: 'POST'
    });
  }
};

// Helper function to get current user role
window.getUserRole = async function() {
  try {
    const response = await api('/user');
    return response.data?.role || 'customer';
  } catch (err) {
    return 'customer';
  }
};

// Helper function to check if user is admin
window.isAdmin = async function() {
  const role = await getUserRole();
  return role === 'admin';
};

// Helper function to check if user is vendor
window.isVendor = async function() {
  const role = await getUserRole();
  return role === 'vendor';
};

// Helper function to check if user is customer
window.isCustomer = async function() {
  const role = await getUserRole();
  return role === 'customer';
};

// Expose helpers
window.requireAuth = requireAuth;
window.checkAuthStatus = checkAuthStatus;
window.loadProfile = loadProfile;
window.initEdit = initEdit;
window.loadSoftware = loadSoftware;
