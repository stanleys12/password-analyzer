// Password Analyzer - Comprehensive Security Testing
class PasswordAnalyzer {
    constructor() {
        this.commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'hello',
            'freedom', 'whatever', 'qwerty123', 'trustno1', 'jordan', 'harley',
            'ginger', 'silver', 'michelle', 'blowme', 'corvette', 'yellow', 'dakota',
            'charlie', 'anthony', 'thomas', 'hunter', 'soccer', 'tiger', 'bass',
            'fishing', 'secret', 'guitar', 'hammer', 'silver', 'golden', 'fire',
            'crystal', 'thunder', 'freedom', 'warrior', 'ninja', 'mistress', 'blowjob',
            'porn', 'pornstar', 'vagina', 'penis', 'boobs', 'asshole', 'dick',
            'pussy', 'cock', 'tit', 'fuck', 'shit', 'bitch', 'slut', 'whore'
        ];
        
        this.commonPatterns = [
            /^[0-9]+$/, // Only numbers
            /^[a-z]+$/, // Only lowercase
            /^[A-Z]+$/, // Only uppercase
            /^[a-zA-Z]+$/, // Only letters
            /^(.)\1+$/, // Repeated characters
            /^(.)(.)(\1\2)*$/, // Alternating pattern
            /^(.)\1{2,}$/, // Same character repeated
            /^(.)(.)(\1\2){2,}$/, // Alternating pattern repeated
            /^[a-z]{1,3}$/, // Very short lowercase
            /^[A-Z]{1,3}$/, // Very short uppercase
            /^[0-9]{1,3}$/, // Very short numbers
            /^(.)\1{4,}$/, // 5+ same characters
            /^(.)(.)(\1\2){3,}$/, // Alternating pattern 4+ times
        ];
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const passwordInput = document.getElementById('password');
        const toggleBtn = document.getElementById('togglePassword');
        const analyzeBtn = document.getElementById('analyzeBtn');

        // Toggle password visibility
        toggleBtn.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            toggleBtn.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });

        // Analyze password on button click
        analyzeBtn.addEventListener('click', () => {
            this.analyzePassword(passwordInput.value);
        });

        // Analyze on Enter key
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.analyzePassword(passwordInput.value);
            }
        });
    }

    async analyzePassword(password) {
        if (!password) {
            alert('Please enter a password to analyze.');
            return;
        }

        // Show loading state
        const analyzeBtn = document.getElementById('analyzeBtn');
        const originalText = analyzeBtn.innerHTML;
        analyzeBtn.innerHTML = '<span class="loading"></span> Analyzing...';
        analyzeBtn.disabled = true;

        try {
            // Perform comprehensive analysis
            const analysis = await this.performAnalysis(password);
            
            // Display results
            this.displayResults(analysis);
            
            // Show results section
            document.getElementById('resultsSection').style.display = 'block';
            
        } catch (error) {
            console.error('Analysis error:', error);
            alert('An error occurred during analysis. Please try again.');
        } finally {
            // Restore button state
            analyzeBtn.innerHTML = originalText;
            analyzeBtn.disabled = false;
        }
    }

    async performAnalysis(password) {
        const analysis = {
            password: password,
            length: password.length,
            strength: this.calculateStrength(password),
            vulnerabilities: this.findVulnerabilities(password),
            suggestions: this.generateSuggestions(password),
            timeEstimates: this.calculateTimeEstimates(password),
            attackResults: await this.simulateAttacks(password),
            hashes: this.generateHashes(password)
        };

        return analysis;
    }

    calculateStrength(password) {
        let score = 0;
        let feedback = [];

        // Length scoring
        if (password.length >= 12) {
            score += 25;
        } else if (password.length >= 8) {
            score += 15;
        } else if (password.length >= 6) {
            score += 10;
        } else {
            score += 5;
        }

        // Character variety scoring
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumbers = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);

        if (hasLower) score += 10;
        if (hasUpper) score += 10;
        if (hasNumbers) score += 10;
        if (hasSpecial) score += 15;

        // Pattern detection (penalties)
        if (this.commonPasswords.includes(password.toLowerCase())) {
            score -= 50;
            feedback.push('Common password detected');
        }

        // Check for patterns
        for (const pattern of this.commonPatterns) {
            if (pattern.test(password)) {
                score -= 20;
                feedback.push('Weak pattern detected');
                break;
            }
        }

        // Sequential characters penalty
        if (this.hasSequentialChars(password)) {
            score -= 15;
            feedback.push('Sequential characters detected');
        }

        // Repeated characters penalty
        if (this.hasRepeatedChars(password)) {
            score -= 10;
            feedback.push('Repeated characters detected');
        }

        // Normalize score
        score = Math.max(0, Math.min(100, score));

        // Determine strength level
        let strength;
        if (score >= 80) strength = 'Very Strong';
        else if (score >= 60) strength = 'Strong';
        else if (score >= 40) strength = 'Medium';
        else if (score >= 20) strength = 'Weak';
        else strength = 'Very Weak';

        return { score, strength, feedback };
    }

    hasSequentialChars(password) {
        const sequences = ['123', '234', '345', '456', '567', '678', '789', '890',
                          'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
                          'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr',
                          'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz'];
        
        const lowerPassword = password.toLowerCase();
        return sequences.some(seq => lowerPassword.includes(seq));
    }

    hasRepeatedChars(password) {
        for (let i = 0; i < password.length - 2; i++) {
            if (password[i] === password[i + 1] && password[i] === password[i + 2]) {
                return true;
            }
        }
        return false;
    }

    findVulnerabilities(password) {
        const vulnerabilities = [];

        // Check length
        if (password.length < 8) {
            vulnerabilities.push('Password is too short (less than 8 characters)');
        }

        // Check character variety
        if (!/[a-z]/.test(password)) {
            vulnerabilities.push('Missing lowercase letters');
        }
        if (!/[A-Z]/.test(password)) {
            vulnerabilities.push('Missing uppercase letters');
        }
        if (!/[0-9]/.test(password)) {
            vulnerabilities.push('Missing numbers');
        }
        if (!/[^A-Za-z0-9]/.test(password)) {
            vulnerabilities.push('Missing special characters');
        }

        // Check for common passwords
        if (this.commonPasswords.includes(password.toLowerCase())) {
            vulnerabilities.push('Password is in common password lists');
        }

        // Check for patterns
        for (const pattern of this.commonPatterns) {
            if (pattern.test(password)) {
                vulnerabilities.push('Weak pattern detected');
                break;
            }
        }

        // Check for personal information patterns
        if (this.containsPersonalInfo(password)) {
            vulnerabilities.push('May contain personal information');
        }

        return vulnerabilities;
    }

    containsPersonalInfo(password) {
        const personalPatterns = [
            /(19|20)\d{2}/, // Years
            /\b\d{3}-\d{2}-\d{4}\b/, // SSN pattern
            /\b\d{3}\.\d{2}\.\d{4}\b/, // SSN pattern with dots
            /\b\d{10}\b/, // Phone number
            /\b\d{5}\b/, // ZIP code
        ];
        
        return personalPatterns.some(pattern => pattern.test(password));
    }

    generateSuggestions(password) {
        const suggestions = [];

        // Length suggestions
        if (password.length < 12) {
            suggestions.push('Use at least 12 characters for better security');
        }

        // Character variety suggestions
        if (!/[a-z]/.test(password)) {
            suggestions.push('Add lowercase letters (a-z)');
        }
        if (!/[A-Z]/.test(password)) {
            suggestions.push('Add uppercase letters (A-Z)');
        }
        if (!/[0-9]/.test(password)) {
            suggestions.push('Add numbers (0-9)');
        }
        if (!/[^A-Za-z0-9]/.test(password)) {
            suggestions.push('Add special characters (!@#$%^&*)');
        }

        // Pattern suggestions
        if (this.commonPasswords.includes(password.toLowerCase())) {
            suggestions.push('Avoid common passwords and dictionary words');
        }

        if (this.hasSequentialChars(password)) {
            suggestions.push('Avoid sequential characters (123, abc)');
        }

        if (this.hasRepeatedChars(password)) {
            suggestions.push('Avoid repeated characters (aaa, 111)');
        }

        // Advanced suggestions
        suggestions.push('Consider using a passphrase instead of a single word');
        suggestions.push('Use random character combinations rather than words');
        suggestions.push('Avoid using personal information (birthdays, names)');

        return suggestions;
    }

    calculateTimeEstimates(password) {
        const estimates = [];
        const charset = this.getCharset(password);
        const length = password.length;
        const combinations = Math.pow(charset, length);
        
        // Assuming 1 billion attempts per second (modern GPU)
        const attemptsPerSecond = 1000000000;
        const seconds = combinations / attemptsPerSecond;

        if (seconds < 1) {
            estimates.push({ type: 'instant', time: 'Less than 1 second', color: 'instant' });
        } else if (seconds < 60) {
            estimates.push({ type: 'seconds', time: `${Math.ceil(seconds)} seconds`, color: 'seconds' });
        } else if (seconds < 3600) {
            estimates.push({ type: 'minutes', time: `${Math.ceil(seconds / 60)} minutes`, color: 'minutes' });
        } else if (seconds < 86400) {
            estimates.push({ type: 'hours', time: `${Math.ceil(seconds / 3600)} hours`, color: 'hours' });
        } else if (seconds < 31536000) {
            estimates.push({ type: 'days', time: `${Math.ceil(seconds / 86400)} days`, color: 'days' });
        } else {
            estimates.push({ type: 'years', time: `${Math.ceil(seconds / 31536000)} years`, color: 'years' });
        }

        return estimates;
    }

    getCharset(password) {
        let charset = 0;
        if (/[a-z]/.test(password)) charset += 26;
        if (/[A-Z]/.test(password)) charset += 26;
        if (/[0-9]/.test(password)) charset += 10;
        if (/[^A-Za-z0-9]/.test(password)) charset += 32;
        return charset;
    }

    async simulateAttacks(password) {
        const attacks = [];

        // Dictionary Attack Simulation
        const dictionaryResult = await this.simulateDictionaryAttack(password);
        attacks.push(dictionaryResult);

        // Brute Force Attack Simulation
        const bruteForceResult = await this.simulateBruteForceAttack(password);
        attacks.push(bruteForceResult);

        // Rainbow Table Attack Simulation
        const rainbowTableResult = await this.simulateRainbowTableAttack(password);
        attacks.push(rainbowTableResult);

        // Social Engineering Attack Simulation
        const socialEngineeringResult = await this.simulateSocialEngineeringAttack(password);
        attacks.push(socialEngineeringResult);

        return attacks;
    }

    async simulateDictionaryAttack(password) {
        // Simulate delay for realistic feel
        await this.delay(500);
        
        const isVulnerable = this.commonPasswords.includes(password.toLowerCase()) ||
                            this.isCommonWord(password);
        
        return {
            name: 'Dictionary Attack',
            type: 'dictionary',
            description: 'Tests against common passwords and dictionary words',
            status: isVulnerable ? 'success' : 'failed',
            result: isVulnerable ? 'Password cracked' : 'Attack failed',
            time: isVulnerable ? 'Instant' : 'N/A'
        };
    }

    async simulateBruteForceAttack(password) {
        await this.delay(800);
        
        const charset = this.getCharset(password);
        const length = password.length;
        const combinations = Math.pow(charset, length);
        const attemptsPerSecond = 1000000000; // 1 billion per second
        const timeInSeconds = combinations / attemptsPerSecond;
        
        let timeToCrack;
        if (timeInSeconds < 1) timeToCrack = 'Less than 1 second';
        else if (timeInSeconds < 60) timeToCrack = `${Math.ceil(timeInSeconds)} seconds`;
        else if (timeInSeconds < 3600) timeToCrack = `${Math.ceil(timeInSeconds / 60)} minutes`;
        else if (timeInSeconds < 86400) timeToCrack = `${Math.ceil(timeInSeconds / 3600)} hours`;
        else if (timeInSeconds < 31536000) timeToCrack = `${Math.ceil(timeInSeconds / 86400)} days`;
        else timeToCrack = `${Math.ceil(timeInSeconds / 31536000)} years`;
        
        const isVulnerable = timeInSeconds < 3600; // Vulnerable if crackable in less than 1 hour
        
        return {
            name: 'Brute Force Attack',
            type: 'brute-force',
            description: 'Systematic character combination testing',
            status: isVulnerable ? 'success' : 'failed',
            result: isVulnerable ? 'Password cracked' : 'Attack failed',
            time: timeToCrack
        };
    }

    async simulateRainbowTableAttack(password) {
        await this.delay(600);
        
        // Simulate rainbow table lookup
        const hashedPassword = CryptoJS.MD5(password).toString();
        const isVulnerable = this.isInRainbowTable(hashedPassword);
        
        return {
            name: 'Rainbow Table Attack',
            type: 'rainbow-table',
            description: 'Pre-computed hash table lookup',
            status: isVulnerable ? 'success' : 'failed',
            result: isVulnerable ? 'Hash found in table' : 'Hash not found',
            time: isVulnerable ? 'Instant' : 'N/A'
        };
    }

    async simulateSocialEngineeringAttack(password) {
        await this.delay(400);
        
        const isVulnerable = this.containsPersonalInfo(password) ||
                            this.isPredictablePattern(password);
        
        return {
            name: 'Social Engineering',
            type: 'social-engineering',
            description: 'Personal information and pattern analysis',
            status: isVulnerable ? 'success' : 'failed',
            result: isVulnerable ? 'Password guessed' : 'Attack failed',
            time: isVulnerable ? 'Minutes to hours' : 'N/A'
        };
    }

    isCommonWord(password) {
        const commonWords = ['password', 'admin', 'user', 'login', 'welcome', 'hello', 'test'];
        return commonWords.includes(password.toLowerCase());
    }

    isInRainbowTable(hash) {
        // Simulate rainbow table lookup
        const commonHashes = [
            '5f4dcc3b5aa765d61d8327deb882cf99', // password
            '21232f297a57a5a743894a0e4a801fc3', // admin
            '827ccb0eea8a706c4c34a16891f84e7b', // 12345
        ];
        return commonHashes.includes(hash);
    }

    isPredictablePattern(password) {
        const patterns = [
            /^(.)\1{2,}$/, // Same character repeated
            /^(.)(.)(\1\2)*$/, // Alternating pattern
            /^[0-9]+$/, // Only numbers
            /^[a-z]+$/, // Only lowercase
        ];
        return patterns.some(pattern => pattern.test(password));
    }

    generateHashes(password) {
        return {
            md5: CryptoJS.MD5(password).toString(),
            sha1: CryptoJS.SHA1(password).toString(),
            sha256: CryptoJS.SHA256(password).toString(),
            sha512: CryptoJS.SHA512(password).toString(),
            bcrypt: this.simulateBcrypt(password)
        };
    }

    simulateBcrypt(password) {
        // Simulate bcrypt hash (in real implementation, you'd use a bcrypt library)
        const salt = 'bcrypt_salt_';
        const hash = CryptoJS.SHA256(password + salt).toString();
        return `$2b$10$${salt}${hash.substring(0, 22)}`;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    displayResults(analysis) {
        // Update strength meter
        const strengthMeter = document.getElementById('strengthMeter');
        const strengthText = document.getElementById('strengthText');
        
        strengthMeter.style.width = `${analysis.strength.score}%`;
        strengthText.textContent = analysis.strength.strength;
        strengthText.className = `strength-text strength-${analysis.strength.strength.toLowerCase().replace(' ', '-')}`;

        // Display time estimates
        const timeEstimates = document.getElementById('timeEstimates');
        timeEstimates.innerHTML = analysis.timeEstimates.map(estimate => 
            `<div class="time-estimate ${estimate.color}">
                <span>${estimate.type.charAt(0).toUpperCase() + estimate.type.slice(1)}</span>
                <span>${estimate.time}</span>
            </div>`
        ).join('');

        // Display vulnerabilities
        const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
        if (analysis.vulnerabilities.length > 0) {
            vulnerabilitiesList.innerHTML = analysis.vulnerabilities.map(vuln => 
                `<li><i class="fas fa-exclamation-triangle"></i> ${vuln}</li>`
            ).join('');
        } else {
            vulnerabilitiesList.innerHTML = '<li><i class="fas fa-check-circle"></i> No major vulnerabilities detected</li>';
        }

        // Display suggestions
        const suggestionsList = document.getElementById('suggestionsList');
        suggestionsList.innerHTML = analysis.suggestions.map(suggestion => 
            `<li><i class="fas fa-lightbulb"></i> ${suggestion}</li>`
        ).join('');

        // Display hash comparison
        const hashComparison = document.getElementById('hashComparison');
        hashComparison.innerHTML = Object.entries(analysis.hashes).map(([type, hash]) => 
            `<div class="hash-item">
                <h5>${type.toUpperCase()}</h5>
                <div class="hash-value">${hash}</div>
            </div>`
        ).join('');

        // Display attack simulation results
        const attackResults = document.getElementById('attackResults');
        attackResults.innerHTML = analysis.attackResults.map(attack => 
            `<div class="attack-result ${attack.type}">
                <h5>${attack.name}</h5>
                <p>${attack.description}</p>
                <p><strong>Time:</strong> ${attack.time}</p>
                <span class="attack-status ${attack.status}">${attack.result}</span>
            </div>`
        ).join('');
    }
}

// Initialize the analyzer when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new PasswordAnalyzer();
});
