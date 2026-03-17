(async ()=>{
  const token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJqb2huIiwicm9sZSI6Im1lc2VybyIsImlhdCI6MTc3MzczMjM1NDQsImV4cCI6MTc3Mzc2Njc0NH0.9VSCQSNv2Vxf3KvrYSS4spHFTUDsmJBtE81dZpefSc0';
  const body={items:[{plate:'ABC123',location:'parqueadero',size:'galleta',sabores:['galleta'],extras:{salsa:false,tajin:false,chispa:false,galleta:0},observation:'solo galleta',quantity:2,unitTotal:500,total:1000}]};
  const res = await fetch('http://localhost:4000/orders', {
    method:'POST', headers:{'Content-Type':'application/json', Authorization:'Bearer '+token}, body:JSON.stringify(body)
  });
  const t = await res.text();
  console.log('status', res.status, res.statusText);
  console.log('body', t);
})();
