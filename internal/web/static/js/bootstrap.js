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
 return err.status===503 || err.status===504 || err.network===true;
}

// Three retries per page bootstrap, including manual Retry clicks. Once the
// budget is exhausted, never silently turn a SID login into an anonymous read.
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
    if (!transientAuthError(err)) { params={}; throw err; }
    if (attempt===3) {
     params={};
     failure=Object.assign(new Error('Connection temporarily unavailable. Reopen QNAPFileManager from QTS to try again.'),{network:true});
     throw failure;
    }
    await sleep(250 * 2**attempt);
   }
  }
 };
}
