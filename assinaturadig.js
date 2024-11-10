const crypto = require('crypto');
const fs = require('fs');


// Gera as chaves pública e privada para uso em assinatura digital.
//Verifica se as chaves já existem e, caso contrário, as gera e salva nos arquivos "private.pem" e "public.pem".
//A chave privada é protegida com uma senha.

function generateKeys() {

  if (fs.existsSync('private.pem') && fs.existsSync('public.pem')) {
    console.log('As chaves já existem.');
    return;
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048, 
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'senha-secreta' 
    }
  });


  fs.writeFileSync('private.pem', privateKey);
  fs.writeFileSync('public.pem', publicKey);

  console.log('Chaves pública e privada geradas com sucesso!');
}



//Função para assinar o texto com a chave privada
function signText(text) {
  const privateKey = fs.readFileSync('private.pem', 'utf8');
  const sign = crypto.createSign('SHA256');
  sign.update(text); // Passa o texto para ser assinado
  sign.end();

  // Gera a assinatura com a chave privada
  const signature = sign.sign({
    key: privateKey,
    passphrase: 'senha-secreta' 
  });

  return signature.toString('base64'); // Converte a assinatura para base64
}



//Função para verificar a assinatura com a chave pública
function verifySignature(text, signature) {
  const publicKey = fs.readFileSync('public.pem', 'utf8');
  const verify = crypto.createVerify('SHA256');
  verify.update(text); // Passa o texto para verificar
  verify.end();

  // Verifica a assinatura usando a chave pública
  const isValid = verify.verify(publicKey, signature, 'base64');
  return isValid;
}



//Função principal para rodar tudo
function main() {
  
  generateKeys();


  // Texto a ser assinado
  const text = 'Este é um texto importante!';


  // Assinar o texto
  const signature = signText(text);


  // Exibir o texto e a assinatura
  console.log('Texto original:', text);
  console.log('Assinatura digital:', signature);

  
  // Verificar a assinatura
  const isValid = verifySignature(text, signature);

  // Mostrar se a assinatura é válida ou não
  if (isValid) {
    console.log('A assinatura é válida.');
  } else {
    console.log('A assinatura NÃO é válida.');
  }

  // Alterar o texto e verificar novamente
  const alteredText = 'Este é um texto alterado!';
  const isValidAfterAlteration = verifySignature(alteredText, signature);

  if (isValidAfterAlteration) {
    console.log('A assinatura é válida após alteração (isso não deveria acontecer).');
  } else {
    console.log('A assinatura NÃO é válida após alteração, o texto foi alterado.');
  }
}



main();
