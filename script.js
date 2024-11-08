let publicKey, privateKey;

/*
Geração de Chaves: A função generateKeys() gera um par de chaves pública e privada RSA com 2048 bits usando node-forge e 
as exibe na interface.

Criptografar Mensagem: encryptMessage() utiliza a chave pública para criptografar a mensagem inserida pelo usuário.
A mensagem é codificada em Base64 para facilitar a exibição.

Descriptografar Mensagem: decryptMessage() usa a chave privada para descriptografar a mensagem criptografada em Base64,
retornando o texto original.
*/

// Função para gerar chaves RSA
function generateKeys() {
    const rsa = forge.pki.rsa;
    rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
        if (err) {
            alert("Erro ao gerar chaves!");
            return;
        }
        publicKey = forge.pki.publicKeyToPem(keypair.publicKey);
        privateKey = forge.pki.privateKeyToPem(keypair.privateKey);

        document.getElementById("publicKey").value = publicKey;
        document.getElementById("privateKey").value = privateKey;
    });
}

// Função para criptografar a mensagem
function encryptMessage() {
    const message = document.getElementById("message").value;
    if (!publicKey || !message) {
        alert("Certifique-se de gerar as chaves e inserir uma mensagem.");
        return;
    }

    const publicKeyObject = forge.pki.publicKeyFromPem(publicKey);
    const encrypted = publicKeyObject.encrypt(forge.util.encodeUtf8(message), 'RSA-OAEP');
    const encryptedBase64 = forge.util.encode64(encrypted);

    document.getElementById("output").value = encryptedBase64;
}

// Função para descriptografar a mensagem
function decryptMessage() {
    const encryptedMessage = document.getElementById("message").value;
    if (!privateKey || !encryptedMessage) {
        alert("Certifique-se de gerar as chaves e inserir uma mensagem criptografada.");
        return;
    }

    try {
        const privateKeyObject = forge.pki.privateKeyFromPem(privateKey);
        const encryptedBytes = forge.util.decode64(encryptedMessage);
        const decrypted = privateKeyObject.decrypt(encryptedBytes, 'RSA-OAEP');

        document.getElementById("output").value = forge.util.decodeUtf8(decrypted);
    } catch (e) {
        alert("Erro ao descriptografar a mensagem. Verifique a chave.");
        document.getElementById("output").value = "";
    }
}
