(async ()=>{
  const body={items:[{plate:'ABC123',location:'parqueadero',size:'galleta',sabores:['galleta'],extras:{salsa:false,tajin:false,chispa:false,galleta:0},observation:'solo galleta',quantity:2,unitTotal:500,total:1000}]};
  const res = await fetch('http://localhost:4000/orders', {
    method:'POST',
    headers:{
      'Content-Type':'application/json',
      'Authorization':'Bearer eyJhbGciOiJIUzI1NiIsInVzZXJuYW1lIjoiamhvbmIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NzM3MjUwMzQsImV4cCI6MTc3Mzc2ODIzNH0.P_UP4vSyecCvRns4mC7rY-JocHuJ3DCVWtUIBDe-hdo'
    },
    body:JSON.stringify(body)
  });
  const t = await res.text();
  console.log('status', res.status, res.statusText);
  console.log('body', t);
})();
