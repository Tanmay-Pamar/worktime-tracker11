(function(){
  // Share this device's timezone with the server so "today", "this week" and
  // clock in/out times match your local clock.
  var tzo = String(new Date().getTimezoneOffset());
  var hadCookie = /(?:^|;\s*)tzo=/.test(document.cookie);
  var current = (document.cookie.match(/(?:^|;\s*)tzo=([^;]*)/) || [])[1];
  if (current !== tzo) {
    document.cookie = 'tzo=' + tzo + '; path=/; max-age=31536000; SameSite=Lax';
    if (!hadCookie && !sessionStorage.getItem('tzoReload')) { sessionStorage.setItem('tzoReload','1'); location.reload(); return; }
  }

  function localStamp(){
    var d = new Date(), p = function(n){ return String(n).padStart(2,'0'); };
    return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes());
  }
  document.querySelectorAll('form').forEach(function(form){
    form.addEventListener('submit', function(){
      form.querySelectorAll('.client-now').forEach(function(i){ i.value = localStamp(); });
    });
  });
})();
(function(){
  const timer=document.getElementById('timer');
  if(!timer) return;
  const start=new Date(timer.dataset.start);
  function update(){
    const seconds=Math.max(0,Math.floor((Date.now()-start.getTime())/1000));
    const h=String(Math.floor(seconds/3600)).padStart(2,'0');
    const m=String(Math.floor((seconds%3600)/60)).padStart(2,'0');
    const s=String(seconds%60).padStart(2,'0');
    timer.textContent=`${h}:${m}:${s}`;
  }
  update(); setInterval(update,1000);
})();
