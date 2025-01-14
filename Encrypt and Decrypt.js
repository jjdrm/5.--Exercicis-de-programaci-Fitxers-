const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

// Function to generate a random AES key
function generateKey() {
    return crypto.randomBytes(32); // 256-bit key
}

// Function to encrypt data
function encryptData(key, iv, data) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        encryptedData: encrypted.toString('hex'),
        authTag: authTag.toString('hex'),
    };
}

// Function to decrypt data
function decryptData(key, iv, encryptedData, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedData, 'hex')),
        decipher.final(),
    ]);
    return decrypted.toString('utf8');
}

// Function to read input from the user
function askQuestion(query) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    return new Promise((resolve) => rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    }));
}

// Main function to handle encryption and decryption
async function main() {
    console.log("Welcome to the File Encryption/Decryption App!");

    // Ask if the user wants to encrypt or decrypt
    const action = await askQuestion("Do you want to encrypt or decrypt? (e/d): ");

    if (action.toLowerCase() === 'e') {
        // Encryption
        const filePath = await askQuestion("Enter the path to the file you want to encrypt: ");

        // Read file contents
        if (!fs.existsSync(filePath)) {
            console.error("File does not exist. Please check the path and try again.");
            return;
        }
        const fileContent = fs.readFileSync(filePath, 'utf8');

        const key = generateKey();
        const iv = crypto.randomBytes(16); // Initialization Vector (16 bytes for AES-GCM)

        const encrypted = encryptData(key, iv, fileContent);

        // Save the encrypted content, key, and IV to separate files
        fs.writeFileSync('encrypted.txt', `Encrypted Data: ${encrypted.encryptedData}\nIV: ${iv.toString('hex')}\nAuth Tag: ${encrypted.authTag}`, 'utf8');
        fs.writeFileSync('key.txt', key.toString('hex'), 'utf8');

        console.log("Encryption complete. Encrypted data and key have been saved.");
    } else if (action.toLowerCase() === 'd') {
        // Decryption
        const encryptedFile = await askQuestion("Enter the path to the encrypted file: ");
        const keyFile = await askQuestion("Enter the path to the key file: ");

        // Read encrypted data and key
        if (!fs.existsSync(encryptedFile) || !fs.existsSync(keyFile)) {
            console.error("One or more files do not exist. Please check the paths and try again.");
            return;
        }

        const encryptedDataContent = fs.readFileSync(encryptedFile, 'utf8');
        const key = Buffer.from(fs.readFileSync(keyFile, 'utf8'), 'hex');

        // Extract encrypted data, IV, and auth tag from the file
        const [encryptedHex, ivHex, authTagHex] = encryptedDataContent.split('\n').map(line => line.split(': ')[1]);
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = authTagHex;

        try {
            const decrypted = decryptData(key, iv, encryptedHex, authTag);
            fs.writeFileSync('decrypted.txt', decrypted, 'utf8');
            console.log("Decryption complete. Decrypted data has been saved to decrypted.txt");
        } catch (error) {
            console.error("Decryption failed. Please check your key and data files.");
        }
    } else {
        console.log("Invalid option. Please restart the program and choose 'e' or 'd'.");
    }
}

main();
