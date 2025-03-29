// Client-side security configuration
const securityConfig = {
    // Content Security Policy
    csp: {
        defaultSrc: ["'self'"],
        scriptSrc: [
            "'self'",
            "'unsafe-inline'", // Required for Tailwind
            "https://cdn.tailwindcss.com"
        ],
        styleSrc: [
            "'self'",
            "'unsafe-inline'",
            "https://cdn.tailwindcss.com",
            "https://cdnjs.cloudflare.com"
        ],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"]
    },

    // Session security
    session: {
        timeout: 900000, // 15 minutes in ms
        warningTime: 300000, // 5 minute warning
        renewBeforeExpiry: 60000 // 1 minute before expiry
    },

    // Input validation
    inputValidation: {
        username: /^[a-zA-Z0-9_]{4,20}$/,
        password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/,
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        accountNumber: /^\d{10,20}$/
    },

    // Security headers to be set via meta tags
    securityHeaders: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    },

    // Security event logging
    logSecurityEvent: (event) => {
        console.log(`[Security Event] ${new Date().toISOString()}: ${event}`);
        // In production, this would send to a security monitoring service
    }
};

// Apply security headers as meta tags
function applySecurityHeaders() {
    const meta = document.createElement('meta');
    meta.httpEquiv = "Content-Security-Policy";
    meta.content = Object.entries(securityConfig.csp)
        .map(([key, values]) => `${key} ${values.join(' ')}`)
        .join('; ');
    document.head.appendChild(meta);

    for (const [header, value] of Object.entries(securityConfig.securityHeaders)) {
        const meta = document.createElement('meta');
        meta.httpEquiv = header;
        meta.content = value;
        document.head.appendChild(meta);
    }
}

// Initialize client-side security
document.addEventListener('DOMContentLoaded', () => {
    applySecurityHeaders();
    
    // Force HTTPS in production
    if (window.location.protocol !== 'https:' && !window.location.hostname.includes('localhost')) {
        window.location.href = window.location.href.replace('http:', 'https:');
    }
});

export default securityConfig;