# Password Analyzer Test Examples

Here are some example passwords to test the analyzer with their expected results:

## Weak Passwords (Should Fail Multiple Tests)

### 1. "password"

- **Strength**: Very Weak
- **Dictionary Attack**: ✅ Cracked instantly
- **Brute Force**: ✅ Cracked in seconds
- **Vulnerabilities**: Common password, too short, only lowercase
- **Suggestions**: Add uppercase, numbers, special characters, use longer password

### 2. "123456"

- **Strength**: Very Weak
- **Dictionary Attack**: ✅ Cracked instantly
- **Brute Force**: ✅ Cracked instantly
- **Vulnerabilities**: Common password, only numbers, sequential pattern
- **Suggestions**: Add letters, avoid sequences, use longer password

### 3. "abc123"

- **Strength**: Weak
- **Dictionary Attack**: ✅ Cracked instantly
- **Brute Force**: ✅ Cracked in seconds
- **Vulnerabilities**: Common pattern, too short, predictable
- **Suggestions**: Add special characters, use longer password

## Medium Strength Passwords

### 4. "MyPassword123"

- **Strength**: Medium
- **Dictionary Attack**: ❌ Attack failed
- **Brute Force**: ✅ Cracked in minutes to hours
- **Vulnerabilities**: Contains dictionary word, predictable pattern
- **Suggestions**: Add special characters, use random combinations

### 5. "SecurePass2023"

- **Strength**: Medium to Strong
- **Dictionary Attack**: ❌ Attack failed
- **Brute Force**: ✅ Cracked in hours to days
- **Vulnerabilities**: Contains dictionary words, predictable pattern
- **Suggestions**: Use random characters instead of words

## Strong Passwords (Should Pass Most Tests)

### 6. "K9#mP$2xL@vR8"

- **Strength**: Strong to Very Strong
- **Dictionary Attack**: ❌ Attack failed
- **Brute Force**: ❌ Attack failed (years to crack)
- **Vulnerabilities**: None detected
- **Suggestions**: Consider using a passphrase for better memorability

### 7. "Tr0ub4dor&3"

- **Strength**: Strong
- **Dictionary Attack**: ❌ Attack failed
- **Brute Force**: ❌ Attack failed (days to years)
- **Vulnerabilities**: May contain predictable substitutions
- **Suggestions**: Use completely random characters

### 8. "correct horse battery staple"

- **Strength**: Very Strong
- **Dictionary Attack**: ❌ Attack failed
- **Brute Force**: ❌ Attack failed (centuries to crack)
- **Vulnerabilities**: None detected
- **Suggestions**: Excellent passphrase example

## Edge Cases

### 9. "aaaaaaaaaa"

- **Strength**: Very Weak
- **Vulnerabilities**: Repeated characters, too short, only lowercase
- **Suggestions**: Add variety, avoid repetition

### 10. "qwertyuiop"

- **Strength**: Weak
- **Vulnerabilities**: Keyboard pattern, only lowercase
- **Suggestions**: Avoid keyboard patterns, add variety

### 11. "P@ssw0rd!"

- **Strength**: Medium
- **Vulnerabilities**: Common word with substitutions
- **Suggestions**: Use random characters instead of word substitutions

## Testing Instructions

1. Open the password analyzer in your browser
2. Try each example password above
3. Compare the results with the expected outcomes
4. Note how different attack methods perform
5. Observe the hash comparison differences
6. Test your own passwords (but not real ones!)

## Expected Hash Outputs

When you test "password", you should see:

- **MD5**: 5f4dcc3b5aa765d61d8327deb882cf99
- **SHA1**: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
- **SHA256**: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
- **SHA512**: b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86
- **Bcrypt**: $2b$10$bcrypt_salt_5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

## Security Notes

- **Never test real passwords** you use for important accounts
- **Use test passwords** like the examples above
- **The analysis is educational** and may not catch all vulnerabilities
- **Real-world attacks** may use different techniques
- **Always follow** your organization's password policies
