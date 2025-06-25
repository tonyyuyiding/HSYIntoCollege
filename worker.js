export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (!env.USERNAME || !env.PASSWORD) {
            return new Response('Internal Server Error', { status: 500 });
        }

        if (url.pathname.match(/\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2)$/i)) {
            return env.ASSETS.fetch(request);
        }

        const cookies = request.headers.get('Cookie') || '';
        const hasAuthCookie = cookies.includes(`hsy_auth=${env.USERNAME}&${env.PASSWORD}`);

        if (url.pathname === '/login') {

            const auth = request.headers.get('Authorization');
            if (!auth || !auth.startsWith('Basic ')) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: { 'WWW-Authenticate': 'Basic realm="Login Required"' },
                });
            }

            const credentials = atob(auth.split(' ')[1]);
            const [username, password] = credentials.split(':');

            if (username !== env.USERNAME || password !== env.PASSWORD) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: { 'WWW-Authenticate': 'Basic realm="Login Required"' },
                });
            } else {
                const next = url.searchParams.get('next') || '/';
                const safeNext = decodeURIComponent(next);
                
                const html = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Successful</title>
                    <meta http-equiv="refresh" content="1;url=${encodeURI(safeNext)}">
                </head>
                <body>
                    <p>Login successful, redirecting...</p>
                    <script>
                        setTimeout(() => { window.location.href = "${safeNext.replace(/"/g, '\\"')}"; }, 500);
                    </script>
                </body>
                </html>`;

                return new Response(html, {
                    status: 200,
                    headers: {
                        'Content-Type': 'text/html',
                        'Set-Cookie': `hsy_auth=${username}&${password}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`
                    }
                });
            }
        }

        if (hasAuthCookie) {
            return env.ASSETS.fetch(request);
        } else {
            const encodedUrl = encodeURIComponent(url.toString());
            return Response.redirect(`${url.origin}/login?next=${encodedUrl}`, 302);
        }
    }
};