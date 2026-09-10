// Capture bootstrap credentials before scrubbing the current history entry.
export function sessionQuery(search) {
 const query=new URLSearchParams(search);
 if (!query.has('sid')) return {};
 const params={sid:query.get('sid')};
 if (query.has('user')) params.user=query.get('user');
 return params;
}
export function cleanSessionURL(href) {
 const url=new URL(href);
 url.searchParams.delete('sid');
 url.searchParams.delete('user');
 return url.pathname+url.search+url.hash;
}

export function transientAuthError(err) {
 return err.status===429 || err.status===503 || err.status===504 || err.network===true;
}

function retryDelay(err,attempt) {
 const fallback=250 * 2**attempt;
 if (err.retryAfter==null) return fallback;
 const value=String(err.retryAfter).trim();
 const delay=/^\d+$/.test(value) ? Number(value)*1000 :
  /^[A-Za-z]{3},/.test(value) ? Date.parse(value)-Date.now() : NaN;
 return Number.isNaN(delay) ? fallback : Math.min(5000,Math.max(0,delay));
}

// Three retries per attempt. SID exhaustion is terminal across manual Retry
// clicks; cookie authentication can start a fresh bounded attempt each time.
export function sessionBootstrap(href,replaceURL,request,sleep=ms => new Promise(resolve => setTimeout(resolve,ms))) {
 let params=sessionQuery(new URL(href).search),failure=null;
 replaceURL(cleanSessionURL(href));
 href=''; // Do not retain a second copy of the credentials in this closure.
 return async function connect(valid=() => true) {
  if (failure) throw failure;
  for (let attempt=0; ; attempt++) {
   if (!valid()) { params={}; return null; }
   try {
    const session=await request(params);
    params={};
    return session;
   } catch(err) {
    if (err.status===401) { params={}; throw err; }
    if (!transientAuthError(err)) throw err;
    if (attempt===3) {
     const pendingSID=Object.hasOwn(params,'sid');
     params={};
     const exhausted=Object.assign(new Error(pendingSID ?
      'Connection temporarily unavailable. Reopen QNAPFileManager from QTS to try again.' :
      'Connection temporarily unavailable. Please retry.'),{network:true});
     if (pendingSID) failure=exhausted;
     throw exhausted;
    }
    await sleep(retryDelay(err,attempt));
   }
  }
 };
}
