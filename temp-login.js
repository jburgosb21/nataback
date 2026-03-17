(async ()=>{
  const credentials={username:'jhonb',password:'123456'};
  const res = await fetch('http://localhost:4000/auth/login', {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(credentials)
  });
  const t = await res.text();
  console.log('login status', res.status, res.statusText, 'body', t);
})();
