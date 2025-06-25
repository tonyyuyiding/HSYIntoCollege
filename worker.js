export default {
    async fetch(request, env, ctx) {
        // Check for Authorization header
        const auth = request.headers.get('Authorization');
        if (!auth || !auth.startsWith('Basic ')) {
            return new Response('Unauthorized', {
                status: 401,
                headers: { 'WWW-Authenticate': 'Basic realm="Login Required"' },
            });
        }

        // Decode the Base64-encoded credentials
        const credentials = atob(auth.split(' ')[1]);
        const [username, password] = credentials.split(':');

        // Verify credentials against environment variables
        if (username !== env.USERNAME || password !== env.PASSWORD) {
            return new Response('Unauthorized', {
                status: 401,
                headers: { 'WWW-Authenticate': 'Basic realm="Login Required"' },
            });
        }

        // If authenticated, serve the Docusaurus static content
        return env.ASSETS.fetch(request);
    },
};