export default {
  async email(message, env, ctx) {
    const subject = message.headers.get("subject");

    if (
      message.from === "noreply@company.com" &&
      message.to === "company@timothechau.vet" &&
      subject.startsWith("Your code is ")
    ) {
      // Regex pour récupérer le code dans le titre
      const match = subject.match(/\d{6}/);
      if (match) {
        await env.BINDING_KV.put("temp_code", match[0]);
      } 
    }
    
    // Forwarding
    await message.forward(env.MAIL_FORWARD);
  },

  // fetch() est utilisé pour chaque requête faite via le web
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    // Check si la valeur après le '/' est dans la liste
    if (env.AUTHORIZED_URLS.includes(pathSegments[0])) {
      // Récupère les 2 codes
      const codeMail = await env.BINDING_KV.get("temp_code");
      const codeTotp = await generateTOTP(env.TOKEN_OTP);

      const response = `Code reçu par mail: ${codeMail}\n\n Code 2FA (valable 30s):\n\n${codeTotp}`
      return new Response(response || "Erreur dans la construction de la réponse");
    }

    return new Response("Unauthorized", { status: 401 });
  },
};

// https://github.com/turistu/totp-in-javascript/blob/main/totp.js
async function generateTOTP(key, secs = 30, digits = 6){
  return hotp(unbase32(key), pack64bu(Date.now() / 1000 / secs), digits);
}
async function hotp(key, counter, digits){
  let y = self.crypto.subtle;
	if(!y) throw Error('no self.crypto.subtle object available');
	let k = await y.importKey('raw', key, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
	return hotp_truncate(await y.sign('HMAC', k, counter), digits);
}
function hotp_truncate(buf, digits){
  let a = new Uint8Array(buf), i = a[19] & 0xf;
	return fmt(10, digits, ((a[i]&0x7f)<<24 | a[i+1]<<16 | a[i+2]<<8 | a[i+3]) % 10**digits);
}
function fmt(base, width, num){
  return num.toString(base).padStart(width, '0')
}
function unbase32(s){
  let t = (s.toLowerCase().match(/\S/g)||[]).map(c => {
    let i = 'abcdefghijklmnopqrstuvwxyz234567'.indexOf(c);
		if(i < 0) throw Error(`bad char '${c}' in key`);
		return fmt(2, 5, i);
	}).join('');
	if(t.length < 8) throw Error('key too short');
	return new Uint8Array(t.match(/.{8}/g).map(d => parseInt(d, 2)));
}
function pack64bu(v){
  let b = new ArrayBuffer(8), d = new DataView(b);
	d.setUint32(0, v / 2**32);
	d.setUint32(4, v);
	return b;
}