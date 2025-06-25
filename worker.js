export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (!env.USERNAME || !env.PASSWORD) {
            return new Response('Internal Server Error', { status: 500 });
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
                return new Response('Login successful, redirecting...', {
                    status: 302,
                    headers: {
                        'Location': '/',
                        'Set-Cookie': `hsy_auth=${username}&${password}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600`
                    }
                });
            }
        }

        if (url.pathname.match(/\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2)$/i)) {
            return env.ASSETS.fetch(request);
        }

        if (hasAuthCookie) {
            return env.ASSETS.fetch(request);
        } else {
            return Response.redirect(`${url.origin}/login`, 302);
        }
    }
};