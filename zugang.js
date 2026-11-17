/* Zugang für die Bearbeiten-Ebene:
   Der GitHub-Schlüssel wird mit dem Passwort verschlüsselt (AES-GCM, PBKDF2 mit 310.000 Runden).
   Ohne das richtige Passwort ist der gespeicherte Text wertlos. */
const ZUGANG = (()=>{
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = buf => { let s=""; const a=new Uint8Array(buf); for(let i=0;i<a.length;i+=0x8000) s+=String.fromCharCode.apply(null,a.subarray(i,i+0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
  async function schluessel(pw, salt){
    const basis = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:310000, hash:"SHA-256"}, basis,
      {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
  }
  return {
    async verschluesseln(text, pw){
      const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, await schluessel(pw,salt), enc.encode(text));
      return ["v1", b64(salt), b64(iv), b64(ct)].join(".");
    },
    async entschluesseln(paket, pw){            // wirft einen Fehler bei falschem Passwort
      const [v, s, i, c] = String(paket).split(".");
      if (v!=="v1") throw new Error("format");
      const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(i)}, await schluessel(pw,unb64(s)), unb64(c));
      return dec.decode(pt);
    },
    textZuB64(t){ return b64(enc.encode(t)); },
    b64ZuText(s){ return dec.decode(unb64(String(s).replace(/\s/g,""))); },
    // GitHub-API
    async gh(token, repo, pfad, opts={}){
      const res = await fetch("https://api.github.com/repos/"+repo+pfad, Object.assign({}, opts, {
        headers: Object.assign({"Authorization":"Bearer "+token, "Accept":"application/vnd.github+json"}, opts.headers||{})
      }));
      return res;
    }
  };
})();
