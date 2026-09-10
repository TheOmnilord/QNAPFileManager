// Keep bootstrap credentials in memory for the first session request only.
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
