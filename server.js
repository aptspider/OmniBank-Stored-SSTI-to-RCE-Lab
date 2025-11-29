const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const nunjucks = require('nunjucks');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

// CONFIGURATION
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Nunjucks Setup
nunjucks.configure({ autoescape: true });

// --- MOCK DATABASE ---
const users = []; // { username, email, password }
const sessions = {}; // { sessionId: { username } }
// Stores messages for users. 
// Key: username, Value: Array of { id, subject, date, read }
const inboxes = {}; 

// --- VULNERABLE EMAIL RENDERER ---
function generateWelcomeEmail(username) {
    //  VULNERABILITY: STORED SSTI
    // The developer concatenates the stored username directly into the email template string.
    // This happens every time the email is VIEWED.
    
    const emailTemplate = `
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 800px; margin: 0 auto; background: #ffffff; border: 1px solid #e5e7eb;">
            <div style="background: #004b87; padding: 20px; border-bottom: 4px solid #fbbf24;">
                <h1 style="color: white; margin: 0; font-size: 24px; font-weight: 300;">OmniBank <span style="font-weight:bold">SecureMessage</span></h1>
            </div>
            <div style="padding: 40px;">
                <p style="color: #333; font-size: 16px;">Dear <strong>${username}</strong>,</p>
                <p style="color: #555; line-height: 1.6;">
                    Welcome to OmniBank Online Banking. Your digital enrollment is complete.
                </p>
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px;">
                    <tr style="background: #f8fafc; border-bottom: 1px solid #e2e8f0;">
                        <td style="padding: 10px; font-weight: bold; color: #475569;">Account Type</td>
                        <td style="padding: 10px; color: #1e293b;">Platinum Checking</td>
                    </tr>
                    <tr style="border-bottom: 1px solid #e2e8f0;">
                        <td style="padding: 10px; font-weight: bold; color: #475569;">Account Number</td>
                        <td style="padding: 10px; color: #1e293b;">...8842</td>
                    </tr>
                    <tr style="background: #f8fafc; border-bottom: 1px solid #e2e8f0;">
                        <td style="padding: 10px; font-weight: bold; color: #475569;">Routing Number</td>
                        <td style="padding: 10px; color: #1e293b;">021000021</td>
                    </tr>
                </table>
                <div style="background: #eff6ff; border-left: 4px solid #004b87; padding: 15px; margin: 20px 0;">
                    <p style="margin: 0; color: #1e3a8a; font-size: 14px;">
                        <strong>Security Tip:</strong> Never share your one-time passcode (OTP) with anyone. OmniBank employees will never ask for it.
                    </p>
                </div>
                <p style="color: #555; font-size: 14px;">
                    To view your statements or manage alerts, please visit the <a href="/dashboard" style="color: #004b87;">Account Dashboard</a>.
                </p>
            </div>
            <div style="background: #f9fafb; padding: 20px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e5e7eb;">
                &copy; 2024 OmniBank N.A. Member FDIC. Equal Housing Lender.<br>
                Rendered by Nunjucks v3.2 System.
            </div>
        </div>
    `;

    try {
        // Renders the template. If username contains {{ ... }}, it executes here.
        return nunjucks.renderString(emailTemplate);
    } catch (e) {
        return `<div style="color:red; padding: 20px;"><strong>System Error Rendering Template:</strong> ${e.message}</div>`;
    }
}

// --- HELPER: AUTH CHECK ---
function checkAuth(req, res, next) {
    const session = sessions[req.cookies.session_id];
    if (!session) {
        return res.redirect('/login');
    }
    req.user = session;
    next();
}

// --- ROUTES ---

// 1. ROOT (Redirect logic)
app.get('/', (req, res) => {
    if (req.cookies.session_id && sessions[req.cookies.session_id]) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

// 2. AUTHENTICATION
app.get('/login', (req, res) => res.send(renderAuthPage('login', req.query.error)));
app.get('/register', (req, res) => res.send(renderAuthPage('register', req.query.error)));

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        const sessionId = crypto.randomUUID();
        sessions[sessionId] = user;
        res.cookie('session_id', sessionId);
        return res.redirect('/dashboard');
    }
    res.redirect('/login?error=Invalid Credentials');
});

app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.redirect('/register?error=All fields are required');
    }
    
    // Store User
    // Vulnerability Note: 'username' is stored as-is (with payload).
    users.push({ username, email, password });
    
    // Create Welcome Message in Inbox
    if (!inboxes[username]) inboxes[username] = [];
    inboxes[username].push({
        id: 101,
        subject: 'Welcome to OmniBank Online Banking',
        date: new Date().toLocaleDateString(),
        sender: 'OmniBank Service Team'
    });
    
    // Auto Login
    const sessionId = crypto.randomUUID();
    sessions[sessionId] = { username, email };
    res.cookie('session_id', sessionId);
    
    res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
    if (req.cookies.session_id) {
        delete sessions[req.cookies.session_id];
        res.clearCookie('session_id');
    }
    res.redirect('/login');
});

// 3. DASHBOARD (Main Bank View)
app.get('/dashboard', checkAuth, (req, res) => {
    res.send(renderDashboard(req.user, 'overview'));
});

// 4. SECURE MESSAGE CENTER (List View)
app.get('/secure/messages', checkAuth, (req, res) => {
    const userMessages = inboxes[req.user.username] || [];
    res.send(renderDashboard(req.user, 'inbox', userMessages));
});

// 5. MESSAGE VIEWER (VULNERABLE TRIGGER)
app.get('/secure/message/:id', checkAuth, (req, res) => {
    const msgId = parseInt(req.params.id);
    const userMessages = inboxes[req.user.username] || [];
    const message = userMessages.find(m => m.id === msgId);

    if (!message) return res.send("Message not found.");

    // TRIGGER SSTI: We generate the email body NOW, using the stored username
    const bodyContent = generateWelcomeEmail(req.user.username);
    
    res.send(renderDashboard(req.user, 'view_message', { message, bodyContent }));
});


// --- UI TEMPLATES (HTML GENERATORS) ---

function renderAuthPage(mode, error) {
    const isLogin = mode === 'login';
    const title = isLogin ? 'Sign On' : 'Enrollment';
    const action = isLogin ? '/login' : '/register';
    
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>OmniBank | ${title}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap'); body { font-family: 'Roboto', sans-serif; background-color: #f0f4f8; }</style>
    </head>
    <body>
        <!-- Header -->
        <div class="bg-[#004b87] border-b-4 border-[#fbbf24] h-20 flex items-center px-8 shadow-md">
            <div class="flex items-center gap-2 text-white">
                <i class="fa-solid fa-building-columns text-3xl"></i>
                <div>
                    <span class="text-2xl font-bold tracking-tight block leading-none">OMNIBANK</span>
                    <span class="text-[10px] uppercase tracking-widest opacity-80">Global Banking</span>
                </div>
            </div>
        </div>

        <div class="flex justify-center items-center min-h-[calc(100vh-80px)] p-4">
            <div class="w-full max-w-md bg-white rounded shadow-lg border border-gray-200 overflow-hidden">
                <div class="bg-gray-50 p-4 border-b border-gray-200 flex justify-between items-center">
                    <h2 class="text-lg font-bold text-gray-700">${title}</h2>
                    <i class="fa-solid fa-lock text-green-600"></i>
                </div>
                
                <div class="p-8">
                    ${error ? `<div class="bg-red-50 text-red-700 p-3 text-sm border-l-4 border-red-600 mb-6">${error}</div>` : ''}
                    
                    <form action="${action}" method="POST" class="space-y-5">
                        <div>
                            <label class="block text-xs font-bold text-gray-600 uppercase mb-1">Username</label>
                            <input type="text" name="username" class="w-full border border-gray-300 p-2.5 text-sm rounded focus:border-[#004b87] focus:ring-1 focus:ring-[#004b87] outline-none" placeholder="Enter User ID">
                        </div>

                        ${!isLogin ? `
                        <div>
                            <label class="block text-xs font-bold text-gray-600 uppercase mb-1">Email Address</label>
                            <input type="email" name="email" class="w-full border border-gray-300 p-2.5 text-sm rounded focus:border-[#004b87] focus:ring-1 focus:ring-[#004b87] outline-none" placeholder="name@example.com">
                        </div>
                        ` : ''}
                        
                        <div>
                            <label class="block text-xs font-bold text-gray-600 uppercase mb-1">Password</label>
                            <input type="password" name="password" class="w-full border border-gray-300 p-2.5 text-sm rounded focus:border-[#004b87] focus:ring-1 focus:ring-[#004b87] outline-none" placeholder="••••••••">
                        </div>

                        <button class="w-full bg-[#004b87] hover:bg-[#003865] text-white font-bold py-2.5 rounded shadow transition">
                            ${isLogin ? 'Sign On' : 'Complete Enrollment'}
                        </button>
                    </form>

                    <div class="mt-6 pt-6 border-t border-gray-100 text-center text-sm">
                        ${isLogin 
                            ? `<p class="text-gray-600">New user? <a href="/register" class="text-[#004b87] font-bold hover:underline">Enroll now</a></p>` 
                            : `<p class="text-gray-600">Already enrolled? <a href="/login" class="text-[#004b87] font-bold hover:underline">Log In</a></p>`
                        }
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    `;
}

function renderDashboard(user, view, data) {
    // Determine content based on view
    let mainContent = '';
    
    if (view === 'overview') {
        mainContent = `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <!-- Balance Card -->
                <div class="col-span-2 bg-white rounded shadow-sm border border-gray-200 overflow-hidden">
                    <div class="bg-gray-50 px-6 py-3 border-b border-gray-200 flex justify-between items-center">
                        <span class="font-bold text-gray-700 text-sm">Platinum Checking (...8842)</span>
                        <span class="text-xs text-green-600 font-bold">Active</span>
                    </div>
                    <div class="p-6">
                        <div class="text-sm text-gray-500 mb-1">Available Balance</div>
                        <div class="text-4xl font-bold text-[#004b87]">$24,500.00</div>
                        <div class="mt-6 flex gap-3">
                            <button class="bg-[#004b87] text-white px-4 py-2 rounded text-sm font-medium">Transfer</button>
                            <button class="border border-gray-300 text-gray-700 px-4 py-2 rounded text-sm font-medium hover:bg-gray-50">Pay Bills</button>
                        </div>
                    </div>
                </div>
                
                <!-- Promo -->
                <div class="bg-gradient-to-br from-[#004b87] to-blue-600 rounded shadow-sm p-6 text-white">
                    <h3 class="font-bold text-lg mb-2">Mobile Deposit</h3>
                    <p class="text-sm opacity-90 mb-4">Deposit checks securely from anywhere using the OmniBank Mobile App.</p>
                    <button class="bg-white/20 hover:bg-white/30 text-white text-xs px-3 py-1.5 rounded">Learn More</button>
                </div>
            </div>
            
            <div class="bg-white rounded shadow-sm border border-gray-200">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h3 class="font-bold text-gray-700 text-sm">Recent Activity</h3>
                </div>
                <div class="divide-y divide-gray-100">
                    <div class="px-6 py-4 flex justify-between text-sm">
                        <div>
                            <div class="font-bold text-gray-800">Starbucks Coffee</div>
                            <div class="text-xs text-gray-500">Nov 28 - Debit Card</div>
                        </div>
                        <div class="font-mono text-gray-800">-$5.40</div>
                    </div>
                    <div class="px-6 py-4 flex justify-between text-sm">
                        <div>
                            <div class="font-bold text-gray-800">Direct Deposit - Payroll</div>
                            <div class="text-xs text-gray-500">Nov 25 - ACH Credit</div>
                        </div>
                        <div class="font-mono text-green-600">+$3,200.00</div>
                    </div>
                </div>
            </div>
        `;
    } else if (view === 'inbox') {
        const messages = data;
        const msgList = messages.length > 0 
            ? messages.map(m => `
                <a href="/secure/message/${m.id}" class="block bg-white hover:bg-blue-50 border-b border-gray-100 p-4 transition group">
                    <div class="flex justify-between items-center mb-1">
                        <span class="font-bold text-sm text-[#004b87] group-hover:underline">${m.sender}</span>
                        <span class="text-xs text-gray-500">${m.date}</span>
                    </div>
                    <div class="text-sm text-gray-800 font-medium">${m.subject}</div>
                    <div class="text-xs text-gray-500 mt-1">Click to view secure message content...</div>
                </a>
            `).join('')
            : '<div class="p-8 text-center text-gray-500 italic">No messages in your secure inbox.</div>';

        mainContent = `
            <h2 class="text-2xl font-light text-gray-800 mb-6">Secure Message Center</h2>
            <div class="bg-white rounded shadow-sm border border-gray-200 overflow-hidden">
                <div class="bg-gray-50 px-4 py-2 border-b border-gray-200 flex gap-4 text-sm text-gray-600">
                    <button class="font-bold text-[#004b87] border-b-2 border-[#004b87] px-2 py-1">Inbox</button>
                    <button class="hover:text-gray-900 px-2 py-1">Sent</button>
                    <button class="hover:text-gray-900 px-2 py-1">Archive</button>
                </div>
                <div class="divide-y divide-gray-100">
                    ${msgList}
                </div>
            </div>
        `;
    } else if (view === 'view_message') {
        const { message, bodyContent } = data;
        mainContent = `
            <div class="mb-4">
                <a href="/secure/messages" class="text-sm text-gray-500 hover:text-[#004b87]"><i class="fa-solid fa-arrow-left mr-1"></i> Back to Inbox</a>
            </div>
            <div class="bg-white rounded shadow-sm border border-gray-200 overflow-hidden">
                <div class="bg-gray-50 px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-bold text-gray-800">${message.subject}</h2>
                    <div class="flex justify-between items-center mt-2 text-sm">
                        <span class="text-gray-600">From: <strong>${message.sender}</strong></span>
                        <span class="text-gray-500">${message.date}</span>
                    </div>
                </div>
                <div class="p-0">
                    <!-- EMAIL CONTENT (Where SSTI Renders) -->
                    ${bodyContent}
                </div>
            </div>
        `;
    }

    // SANITIZE USERNAME FOR UI (Prevent XSS, we want SSTI)
    const safeUser = user.username.replace(/</g, '&lt;').replace(/>/g, '&gt;');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>OmniBank | Online Banking</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap'); body { font-family: 'Roboto', sans-serif; background-color: #f0f4f8; }</style>
    </head>
    <body class="flex flex-col min-h-screen">
        <!-- Navbar -->
        <nav class="bg-[#004b87] text-white shadow-md z-50">
            <div class="max-w-7xl mx-auto px-6 h-16 flex justify-between items-center">
                <div class="flex items-center gap-8">
                    <a href="/dashboard" class="flex items-center gap-2">
                        <i class="fa-solid fa-building-columns text-2xl"></i>
                        <span class="text-xl font-bold tracking-tight">OMNIBANK</span>
                    </a>
                    <div class="hidden md:flex gap-6 text-sm font-medium">
                        <a href="/dashboard" class="${view === 'overview' ? 'text-white border-b-2 border-white pb-1' : 'text-blue-200 hover:text-white'}">Accounts</a>
                        <a href="#" class="text-blue-200 hover:text-white">Transfers</a>
                        <a href="#" class="text-blue-200 hover:text-white">Bill Pay</a>
                        <a href="/secure/messages" class="${view.includes('message') ? 'text-white border-b-2 border-white pb-1' : 'text-blue-200 hover:text-white'}">
                            Messages <span class="bg-red-500 text-[10px] px-1.5 rounded-full ml-1">1</span>
                        </a>
                    </div>
                </div>
                <div class="flex items-center gap-4 text-sm">
                    <span class="hidden md:inline text-blue-100">Welcome, <strong>${safeUser}</strong></span>
                    <a href="/logout" class="bg-[#003865] hover:bg-[#002845] px-4 py-1.5 rounded text-xs font-bold uppercase tracking-wide transition">Sign Off</a>
                </div>
            </div>
        </nav>

        <!-- Main Layout -->
        <div class="flex-grow max-w-7xl mx-auto w-full p-6 grid grid-cols-1 md:grid-cols-4 gap-6">
            <!-- Sidebar -->
            <aside class="hidden md:block col-span-1 space-y-6">
                <div class="bg-white rounded shadow-sm border border-gray-200 overflow-hidden">
                    <div class="p-4 bg-gray-50 border-b border-gray-200">
                        <h3 class="text-xs font-bold text-gray-500 uppercase">My Profile</h3>
                    </div>
                    <div class="p-2">
                        <a href="/dashboard" class="flex items-center gap-3 px-3 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-[#004b87] rounded transition ${view === 'overview' ? 'bg-blue-50 text-[#004b87] font-bold' : ''}">
                            <i class="fa-solid fa-wallet w-5"></i> Account Overview
                        </a>
                        <a href="/secure/messages" class="flex items-center gap-3 px-3 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-[#004b87] rounded transition ${view.includes('message') ? 'bg-blue-50 text-[#004b87] font-bold' : ''}">
                            <i class="fa-solid fa-envelope w-5"></i> Secure Inbox
                        </a>
                        <a href="#" class="flex items-center gap-3 px-3 py-2 text-gray-700 hover:bg-blue-50 hover:text-[#004b87] text-sm rounded transition">
                            <i class="fa-solid fa-gear w-5"></i> Settings
                        </a>
                    </div>
                </div>
                
                <div class="bg-gradient-to-b from-[#004b87] to-blue-700 rounded shadow-sm p-5 text-white text-center">
                    <i class="fa-solid fa-shield-halved text-3xl mb-3 opacity-80"></i>
                    <h4 class="font-bold text-sm mb-2">Security Check</h4>
                    <p class="text-xs opacity-90 mb-4">Your account is protected by OmniGuard™.</p>
                    <button class="text-xs border border-white/40 hover:bg-white/10 px-4 py-1.5 rounded">View Status</button>
                </div>
            </aside>

            <!-- Dynamic Content -->
            <section class="col-span-3">
                ${mainContent}
            </section>
        </div>

        <!-- Footer -->
        <footer class="bg-white border-t border-gray-200 mt-auto py-8">
            <div class="max-w-7xl mx-auto px-6 text-center text-xs text-gray-500">
                <div class="flex justify-center gap-6 mb-4">
                    <a href="#" class="hover:underline">Privacy</a>
                    <a href="#" class="hover:underline">Security</a>
                    <a href="#" class="hover:underline">Terms of Use</a>
                    <a href="#" class="hover:underline">Locations</a>
                </div>
                <p>&copy; 2024 OmniBank Corporation. Member FDIC. Equal Housing Lender.</p>
            </div>
        </footer>
    </body>
    </html>
    `;
}

app.listen(PORT, () => {
    console.log(`[LAB] OmniBank Stored SSTI running at http://localhost:${PORT}`);
});
