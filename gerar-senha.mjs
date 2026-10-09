// Uso: node gerar-senha.mjs usuario "senha"
// Imprime a linha para colocar na variável AUTH_USERS do Netlify.
import crypto from 'node:crypto';
const [usuario, senha] = process.argv.slice(2);
if (!usuario || !senha) {
  console.log('Uso: node gerar-senha.mjs usuario "senha"');
  process.exit(1);
}
const iter = 210000;
const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(senha, salt, iter, 32, 'sha256');
const h = `pbkdf2$${iter}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
console.log(`"${usuario.toLowerCase()}": "${h}"`);
console.log('\nCole essa linha dentro das chaves do AUTH_USERS, separando usuários por vírgula.');
