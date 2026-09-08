/**
 * Plain async API client for OAuth service endpoints.
 * Structured to be directly reused by a future React or Next.js frontend.
 */

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function handleResponse(response) {
  const isJson = response.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message =
      typeof data === 'object' && data !== null
        ? data.message || data.error || `HTTP ${response.status} Error`
        : data || `HTTP ${response.status} Error`;
    throw new ApiError(message, response.status, data);
  }

  return data;
}

/**
 * Creates/retrieves a user JWT via the development auth stub.
 * POST /users
 */
export async function createUser(email) {
  const response = await fetch('/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email: email.trim().toLowerCase() })
  });
  return handleResponse(response);
}

/**
 * Retrieves the list of active OAuth connections metadata for the current user.
 * GET /auth/connections
 */
export async function getConnections(token) {
  const response = await fetch('/auth/connections', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return handleResponse(response);
}

/**
 * Mints an authorization URL with PKCE challenge for initiating an OAuth flow.
 * GET /auth/:provider/authorize
 */
export async function getAuthUrl(token, provider) {
  const response = await fetch(`/auth/${encodeURIComponent(provider)}/authorize`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return handleResponse(response);
}

/**
 * Revokes and deletes an active OAuth connection.
 * DELETE /auth/:provider/disconnect
 */
export async function disconnect(token, provider) {
  const response = await fetch(`/auth/${encodeURIComponent(provider)}/disconnect`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return handleResponse(response);
}
