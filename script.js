// --- START: WebAuthn Helper Functions ---
// Helper functions to convert between ArrayBuffer and Base64-URL-safe strings
// (needed to store credential IDs in localStorage)
function bufferToUrlBase64(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
        .replace(/\+/g, '-') // Fixed: Escaped '+'
        .replace(/\//g, '_') // Fixed: Escaped '/'
        .replace(/=+$/, '');
}

function urlBase64ToBuffer(base64String) {
    const base64 = base64String.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const paddedBase64 = base64 + '='.repeat(padLength);
    const binaryString = atob(paddedBase64);
    const buffer = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        buffer[i] = binaryString.charCodeAt(i);
    }
    return buffer.buffer;
}
// --- END: WebAuthn Helper Functions ---

// DOM Elements
const citizenPortal = document.getElementById('citizen-portal');
const adminPortal = document.getElementById('admin-portal');
const navCitizenBtn = document.getElementById('nav-citizen-btn');
const navAdminBtn = document.getElementById('nav-admin-btn');
const loginView = document.getElementById('login-view');
const registrationView = document.getElementById('registration-view');
const votingView = document.getElementById('voting-view');
const goToRegisterBtn = document.getElementById('go-to-register-btn');
const goToLoginBtn = document.getElementById('go-to-login-btn');
const adminLoginView = document.getElementById('admin-login-view');
const adminDashboardView = document.getElementById('admin-dashboard-view');
const adminLogoutBtn = document.getElementById('admin-logout-btn');
const messageModal = document.getElementById('message-modal');
const messageTitle = document.getElementById('message-title');
const messageText = document.getElementById('message-text');
const messageOkBtn = document.getElementById('message-ok-btn');
const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const adminLoginForm = document.getElementById('admin-login-form');
const addPartyForm = document.getElementById('add-party-form');
const addCandidateForm = document.getElementById('add-candidate-form');
const unlockResultsForm = document.getElementById('unlock-results-form');
const candidatePartySelect = document.getElementById('candidate-party');
const voterApprovalList = document.getElementById('voter-approval-list');
const resultsLocked = document.getElementById('results-locked');
const resultsUnlocked = document.getElementById('results-unlocked');
const resultsList = document.getElementById('results-list');
const lockResultsBtn = document.getElementById('lock-results-btn');
const userNameDisplay = document.getElementById('user-name-display');
const logoutBtn = document.getElementById('logout-btn');
const candidatesList = document.getElementById('candidates-list');
const votedMessage = document.getElementById('voted-message');

// --- State Variables ---
let currentPortal = 'citizen';
let currentCitizenPage = 'login-view';
let currentAdminPage = 'admin-login-view';
let currentUser = null;
const ADMIN_PASSWORD = "admin";
const RESULTS_CODE = "1234";

// --- Utility Functions ---
function showMessage(title, text) {
    messageTitle.textContent = title;
    messageText.textContent = text;
    messageModal.classList.add('active');
}
messageOkBtn.addEventListener('click', () => {
    messageModal.classList.remove('active');
});

function updatePageVisibility() {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    if (currentPortal === 'citizen') {
        citizenPortal.classList.add('active');
        if (currentCitizenPage === 'login-view') loginView.classList.add('active');
        if (currentCitizenPage === 'registration-view') registrationView.classList.add('active');
        if (currentCitizenPage === 'voting-view') votingView.classList.add('active');
    } else if (currentPortal === 'admin') {
        adminPortal.classList.add('active');
        if (currentAdminPage === 'admin-login-view') adminLoginView.classList.add('active');
        if (currentAdminPage === 'admin-dashboard-view') adminDashboardView.classList.add('active');
    }

}

function goToCitizenPage(pageId) {
    currentPortal = 'citizen';
    currentCitizenPage = pageId;
    navCitizenBtn.classList.add('bg-cyan-600', 'text-white');
    navCitizenBtn.classList.remove('bg-gray-200', 'text-gray-900');
    navAdminBtn.classList.add('bg-gray-200', 'text-gray-900');
    navAdminBtn.classList.remove('bg-cyan-600', 'text-white');
    updatePageVisibility();
}

function goToAdminPage(pageId) {
    currentPortal = 'admin';
    currentAdminPage = pageId;
    navAdminBtn.classList.add('bg-cyan-600', 'text-white');
    navAdminBtn.classList.remove('bg-gray-200', 'text-gray-900');
    navCitizenBtn.classList.add('bg-gray-200', 'text-gray-900');
    navCitizenBtn.classList.remove('bg-cyan-600', 'text-white');
    updatePageVisibility();
}

// --- Database (LocalStorage) Functions ---
function getDb(key) {
    return JSON.parse(localStorage.getItem(key) || 'null');
}

function setDb(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
}

function initializeDatabase() {
    if (!getDb('users')) setDb('users', {});
    if (!getDb('parties')) setDb('parties', []);
    if (!getDb('candidates')) setDb('candidates', []);
}

// --- WebAuthn (Fingerprint) Functions ---
/**
 * Shuru hota hai fingerprint registration process
 */
async function startFingerprintRegistration(formData) {
    const users = getDb('users');
    if (users[formData.voterId]) {
        showMessage("Registration Failed", "A user with this Voter ID already exists.");
        return;
    }

    // 1. Server se challenge maangna (yahaan hum fake challenge banayenge)
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const createOptions = {
        publicKey: {
            challenge: challenge,
            rp: { name: "E-Voting System" }, // Relying Party (aapki website)
            user: {
                id: new TextEncoder().encode(formData.voterId),
                name: formData.email,
                displayName: `${formData.firstName} ${formData.lastName}`, // Fixed: Used template literal
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 algorithm
            authenticatorSelection: {
                authenticatorAttachment: "platform", // "platform" = built-in (fingerprint)
                userVerification: "required",
            },
            timeout: 60000,
            attestation: "none"
        }
    };

    try {
        // 2. Browser ko credential banane bolna (yahaan phone fingerprint maangega)
        const credential = await navigator.credentials.create(createOptions);

        // 3. Success! Credential ko save karna
        const users = getDb('users'); // Re-get DB just in case

        formData.credentialId = bufferToUrlBase64(credential.rawId);
        formData.approved = false; // Admin must approve
        formData.hasVoted = false;

        users[formData.voterId] = formData;
        setDb('users', users);

        console.log("User registered with fingerprint:", formData.voterId);
        showMessage("Success", "Registration successful! Your account is pending admin approval.");
        goToCitizenPage('login-view');

    } catch (err) {
        console.error("Fingerprint registration error:", err);
        showMessage("Registration Failed", "Fingerprint registration failed or was cancelled. Please try again. (Make sure you are on HTTPS)");
    }
}

/**
 * Shuru hota hai voting ke liye fingerprint verification
 * @param {string} candidateId - The ID of the candidate to vote for.
 */
async function startVotingVerification(candidateId) {
    const users = getDb('users');
    const user = users[currentUser];
    if (!user || !user.credentialId) {
        showMessage("Error", "No fingerprint data found for this user.");
        return;
    }

    // 1. Server se challenge maangna (fake challenge)
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const getOptions = {
        publicKey: {
            challenge: challenge,
            allowCredentials: [{
                type: "public-key",
                id: urlBase64ToBuffer(user.credentialId), // Use the saved ID
                transports: ["internal"],
            }],
            userVerification: "required",
            timeout: 60000,
        }
    };

    try {
        // 2. Browser ko credential verify karne bolna (yahaan phone fingerprint maangega)
        const assertion = await navigator.credentials.get(getOptions);

        // 3. Success! Fingerprint matched.
        showMessage("Verifying...", "Fingerprint Matched! Casting Vote...");

        await castVote(candidateId);

        setTimeout(() => {
            showMessage("Success!", "Your vote has been cast successfully.");
            loadVotingPage(); // Refresh voting page
        }, 1500);

    } catch (err) {
        console.error("Fingerprint verification error:", err);
        showMessage("Verification Failed", "Fingerprint did not match or was cancelled. Vote not cast.");
    }
}

// --- Citizen Portal Logic ---
registerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!navigator.credentials || !navigator.credentials.create) {
        showMessage("Unsupported", "Your browser does not support Fingerprint (WebAuthn) security.");
        return;
    }

    const formData = {
        firstName: document.getElementById('reg-first-name').value,
        lastName: document.getElementById('reg-last-name').value,
        voterId: document.getElementById('reg-voter-id').value,
        aadhaar: document.getElementById('reg-aadhaar').value,
        email: document.getElementById('reg-email').value,
        number: document.getElementById('reg-number').value,
        password: document.getElementById('reg-password').value,
    };

    startFingerprintRegistration(formData);

});

loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const voterId = document.getElementById('login-voter-id').value;
    const password = document.getElementById('login-password').value;
    const users = getDb('users');
    const user = users[voterId];

    if (!user) {
        showMessage("Login Failed", "No user found with this Voter ID.");
        return;
    }

    if (user.password !== password) {
        showMessage("Login Failed", "Incorrect password.");
        return;
    }

    if (!user.approved) {
        showMessage("Login Failed", "Your account is still pending admin approval.");
        return;
    }

    if (!user.credentialId) {
        showMessage("Login Failed", "No fingerprint data found. Please re-register.");
        return;
    }

    currentUser = voterId;
    loadVotingPage();
    goToCitizenPage('voting-view');

});

function loadVotingPage() {
    if (!currentUser) return;
    const user = getDb('users')[currentUser];
    userNameDisplay.textContent = user.firstName;

    if (user.hasVoted) {
        votedMessage.classList.remove('hidden');
        candidatesList.innerHTML = '<p class="text-gray-500 text-center col-span-full">You can only vote once.</p>';
    } else {
        votedMessage.classList.add('hidden');
        loadCandidatesForVoting();
    }

}

function loadCandidatesForVoting() {
    const candidates = getDb('candidates');
    const parties = getDb('parties');
    candidatesList.innerHTML = "";

    if (candidates.length === 0) {
        candidatesList.innerHTML = '<p class="text-gray-500 text-center col-span-full">No candidates available for this election.</p>';
        return;
    }

    candidates.forEach(candidate => {
        const party = parties.find(p => p.id === candidate.partyId);
        const partyName = party ? party.name : 'Independent';

        const card = `
            <div class="border rounded-lg shadow-md p-4 text-center bg-white">
                <img src="https://placehold.co/100x100/e2e8f0/334155?text=${candidate.name[0]}" alt="${candidate.name}" class="w-24 h-24 rounded-full mx-auto mb-4 object-cover">
                <h4 class="text-xl font-semibold text-gray-800">${candidate.name}</h4>
                <p class="text-gray-500 mb-4">${partyName}</p>
                <button class="w-full text-white bg-cyan-600 hover:bg-cyan-700 rounded-lg text-sm px-5 py-2.5 vote-btn" data-candidate-id="${candidate.id}">
                    Vote
                </button>
            </div>
        `;
        candidatesList.innerHTML += card;
    });

    document.querySelectorAll('.vote-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const candidateId = btn.dataset.candidateId;

            const candidateName = getDb('candidates').find(c => c.id === candidateId).name;
            if (confirm(`Confirm vote for ${candidateName}?\nThis will require your fingerprint.`)) {
                startVotingVerification(candidateId);
            }
        });
    });

}

async function castVote(candidateId) {
    // Update candidate vote count
    const candidates = getDb('candidates');
    const candidate = candidates.find(c => c.id === candidateId);
    if (candidate) {
        candidate.votes = (candidate.votes || 0) + 1;
        setDb('candidates', candidates);
    }
    // Update user's voted status
    const users = getDb('users');
    users[currentUser].hasVoted = true;
    setDb('users', users);

    console.log(`Vote cast for ${candidate.name} by ${currentUser}`);

}

logoutBtn.addEventListener('click', () => {
    currentUser = null;
    goToCitizenPage('login-view');
});

// --- Admin Portal Logic ---
adminLoginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const pass = document.getElementById('admin-password').value;
    if (pass === ADMIN_PASSWORD) {
        loadAdminDashboard();
        goToAdminPage('admin-dashboard-view');
    } else {
        showMessage("Admin Login Failed", "Incorrect password.");
    }
    adminLoginForm.reset();
});

adminLogoutBtn.addEventListener('click', () => {
    goToAdminPage('admin-login-view');
});

function loadAdminDashboard() {
    loadPartiesForSelect();
    loadVoterApprovals();
    loadResults();
}

function loadPartiesForSelect() {
    const parties = getDb('parties');
    candidatePartySelect.innerHTML = '<option value="">Select Party</option>';
    parties.forEach(party => {
        candidatePartySelect.innerHTML += `<option value="${party.id}">${party.name}</option>`; // Fixed: Used template literal
    });
}

addPartyForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const partyName = document.getElementById('party-name').value;
    if (!partyName) return;
    const parties = getDb('parties');
    const newParty = { id: 'party_' + Date.now(), name: partyName };
    parties.push(newParty);
    setDb('parties', parties);
    showMessage("Success", `Party "${partyName}" added.`); // Fixed: Used template literal
    addPartyForm.reset();
    loadPartiesForSelect();
});

addCandidateForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const candidateName = document.getElementById('candidate-name').value;
    const partyId = document.getElementById('candidate-party').value;
    if (!candidateName || !partyId) {
        showMessage("Error", "Please fill all fields."); return;
    }
    const candidates = getDb('candidates');
    const newCandidate = { id: 'cand_' + Date.now(), name: candidateName, partyId: partyId, votes: 0 };
    candidates.push(newCandidate);
    setDb('candidates', candidates);
    showMessage("Success", `Candidate "${candidateName}" added.`); // Fixed: Used template literal
    addCandidateForm.reset();
});

function loadVoterApprovals() {
    const users = getDb('users');
    const pendingUsers = Object.values(users).filter(user => !user.approved);
    voterApprovalList.innerHTML = "";

    if (pendingUsers.length === 0) {
        voterApprovalList.innerHTML = '<p class="text-gray-500">No pending approvals.</p>'; return;
    }

    pendingUsers.forEach(user => {
        const item = `<div class="flex justify-between items-center p-3 bg-gray-50 rounded-lg"> <div> <p class="font-medium">${user.firstName} ${user.lastName}</p> <p class="text-sm text-gray-500">${user.voterId}</p> </div> <button class="text-white bg-green-500 hover:bg-green-600 text-xs px-3 py-1 rounded-full approve-btn" data-voter-id="${user.voterId}"> Approve </button> </div>`; // Fixed: Used template literal
        voterApprovalList.innerHTML += item;
    });

    document.querySelectorAll('.approve-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            approveVoter(btn.dataset.voterId);
        });
    });
}

function approveVoter(voterId) {
    const users = getDb('users');
    if (users[voterId]) {
        users[voterId].approved = true;
        setDb('users', users);
        showMessage("Success", `User ${voterId} has been approved.`); // Fixed: Used template literal
        loadVoterApprovals();
    }
}

unlockResultsForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const code = document.getElementById('results-code').value;
    if (code === RESULTS_CODE) {
        resultsLocked.classList.add('hidden');
        resultsUnlocked.classList.remove('hidden');
        loadResults();
    } else {
        showMessage("Error", "Incorrect Secure Code.");
    }
    unlockResultsForm.reset();
});

lockResultsBtn.addEventListener('click', () => {
    resultsLocked.classList.remove('hidden');
    resultsUnlocked.classList.add('hidden');
});

function loadResults() {
    const candidates = getDb('candidates');
    const parties = getDb('parties');
    resultsList.innerHTML = "";

    candidates.sort((a, b) => b.votes - a.votes);

    if (candidates.length === 0) {
        resultsList.innerHTML = '<li>No candidates found.</li>'; return;
    }

    candidates.forEach(candidate => {
        const party = parties.find(p => p.id === candidate.partyId);
        const partyName = party ? party.name : 'Independent';
        resultsList.innerHTML += `<li class="flex justify-between items-center p-2 border-b"> <span> <strong class="text-gray-800">${candidate.name}</strong> <span class="text-sm text-gray-500">(${partyName})</span> </span> <strong class="text-cyan-600 text-lg">${candidate.votes} Votes</strong> </li>`; // Fixed: Used template literal
    });
}

// --- Global Event Listeners ---
navCitizenBtn.addEventListener('click', () => goToCitizenPage('login-view'));
navAdminBtn.addEventListener('click', () => goToAdminPage('admin-login-view'));
goToRegisterBtn.addEventListener('click', () => goToCitizenPage('registration-view'));
goToLoginBtn.addEventListener('click', () => goToCitizenPage('login-view'));

// --- App Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    // Dynamically apply the input-field class
    document.querySelectorAll('.input-field').forEach(el => {
        // We use a CSS class defined in style.css now, but Tailwind is still needed for other classes
        // The classList.add is not strictly needed if we apply it in HTML, but good for consistency
        el.classList.add('input-field');
    });
    initializeDatabase();
    goToCitizenPage('login-view');
});
