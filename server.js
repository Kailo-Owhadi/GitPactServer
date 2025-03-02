require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();

// -------------------- Middleware --------------------
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallbackSecret',
  resave: false,
  saveUninitialized: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// -------------------- Atlassian OAuth Flow --------------------
/**
 * We'll do a similar flow for Jira and Confluence, but in reality
 * Atlassian uses the same tokens for Jira and Confluence on the same site.
 * We'll keep separate routes for clarity if needed.
 */

// -------------------- Common Helper to Exchange Code for Tokens --------------------
async function exchangeCodeForTokens(code, redirectUri) {
  const tokenResponse = await axios.post('https://auth.atlassian.com/oauth/token', {
    grant_type: 'authorization_code',
    client_id: process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr',
    client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
    code,
    redirect_uri: redirectUri
  });
  return tokenResponse.data; // { access_token, refresh_token, etc. }
}

// -------------------- Jira OAuth --------------------

// Step 1: Redirect user to Atlassian login for OAuth consent (Jira)
app.get('/auth/jira', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthStateJira = state;
  res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr'}&scope=read%3Ajira-work%20manage%3Ajira-project%20manage%3Ajira-configuration%20read%3Ajira-user%20write%3Ajira-work%20manage%3Ajira-webhook%20manage%3Ajira-data-provider&redirect_uri=${encodeURIComponent(process.env.ATLASSIAN_REDIRECT_URI || 'http://localhost:3000/auth/jira/callback')}&state=${state}&response_type=code&prompt=consent`);
});

// Step 2: Handle Jira callback and exchange code for tokens
app.get('/auth/jira/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).send('Missing code parameter.');
  }
  if (state !== req.session.oauthStateJira) {
    return res.status(403).send('Invalid state parameter.');
  }
  try {
    const redirectUri = process.env.ATLASSIAN_REDIRECT_URI || 'http://localhost:3000/auth/jira/callback';
    const { access_token, refresh_token } = await exchangeCodeForTokens(code, redirectUri);

    // Save in session
    req.session.jiraAccessToken = access_token;
    req.session.jiraRefreshToken = refresh_token;

    // Retrieve accessible resources (sites)
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const sites = resourcesResp.data;
    if (sites.length > 0) {
      // store the first Jira site for simplicity
      const site = sites.find(s => s.scopes.includes('jira'));
      if (site) {
        req.session.jiraSiteId = site.id;
        req.session.jiraSiteUrl = site.url;
      }
    }
    res.redirect('/projects.html'); // or wherever your Projects page is served from
  } catch (err) {
    console.error('Error exchanging code for token (Jira):', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian (Jira)');
  }
});

// -------------------- Confluence OAuth --------------------

// Step 1: Redirect user to Atlassian login for OAuth consent (Confluence)
app.get('/auth/confluence', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthStateConfluence = state;
  // Confluence relevant scopes
  const confluenceScopes = [
    'read:confluence-space.summary',
    'read:confluence-content.summary',
    'write:confluence-content',
    'read:confluence-props',
    'write:confluence-props'
  ].join('%20');

  res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr'}&scope=${confluenceScopes}&redirect_uri=${encodeURIComponent(process.env.ATLASSIAN_CONFLUENCE_REDIRECT_URI || 'http://localhost:3000/auth/confluence/callback')}&state=${state}&response_type=code&prompt=consent`);
});

// Step 2: Handle Confluence callback
app.get('/auth/confluence/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).send('Missing code parameter.');
  }
  if (state !== req.session.oauthStateConfluence) {
    return res.status(403).send('Invalid state parameter.');
  }
  try {
    const redirectUri = process.env.ATLASSIAN_CONFLUENCE_REDIRECT_URI || 'http://localhost:3000/auth/confluence/callback';
    const { access_token, refresh_token } = await exchangeCodeForTokens(code, redirectUri);

    req.session.confluenceAccessToken = access_token;
    req.session.confluenceRefreshToken = refresh_token;

    // Retrieve accessible resources to find Confluence site
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const sites = resourcesResp.data;
    if (sites.length > 0) {
      // store the first site that includes confluence
      const site = sites.find(s => s.scopes.includes('confluence'));
      if (site) {
        req.session.confluenceSiteId = site.id;
        req.session.confluenceSiteUrl = site.url;
      }
    }
    res.redirect('/projects.html'); // or wherever your Projects page is
  } catch (err) {
    console.error('Error exchanging code for token (Confluence):', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian (Confluence)');
  }
});

// -------------------- Jira Endpoints --------------------

// Check Jira connection status
app.get('/api/jira/status', (req, res) => {
  if (req.session.jiraAccessToken && req.session.jiraSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

// Get all Jira projects
app.get('/api/jira/projects', async (req, res) => {
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const projectsUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project`;
    const response = await axios.get(projectsUrl, {
      headers: {
        Authorization: `Bearer ${req.session.jiraAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data); // array of projects
  } catch (err) {
    console.error('Error fetching Jira projects:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira projects' });
  }
});

// Get single Jira project details
app.get('/api/jira/projects/:projectIdOrKey', async (req, res) => {
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const { projectIdOrKey } = req.params;
    const projectUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project/${projectIdOrKey}`;
    const response = await axios.get(projectUrl, {
      headers: {
        Authorization: `Bearer ${req.session.jiraAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira project details:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira project details' });
  }
});

// Update Jira project (limited fields can be updated via PUT)
app.put('/api/jira/projects/:projectIdOrKey', async (req, res) => {
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  const { projectIdOrKey } = req.params;
  const { name, leadAccountId, description } = req.body;

  // Jira's REST API for updating a project is somewhat limited. 
  // Typically, name, description, url, lead accountId can be updated (where permitted).
  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project/${projectIdOrKey}`;
    const response = await axios.put(
      url,
      {
        name,
        description,
        leadAccountId
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.jiraAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error updating Jira project:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to update Jira project' });
  }
});

// Get Jira issues (using search endpoint)
app.get('/api/jira/issues', async (req, res) => {
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const issuesUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/search`;
    const response = await axios.get(issuesUrl, {
      headers: {
        Authorization: `Bearer ${req.session.jiraAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira issues:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira issues' });
  }
});

// Get single Jira issue
app.get('/api/jira/issue/:issueId', async (req, res) => {
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const issueUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue/${req.params.issueId}`;
    const response = await axios.get(issueUrl, {
      headers: {
        Authorization: `Bearer ${req.session.jiraAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira issue:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira issue details' });
  }
});

// Create a new Jira issue
app.post('/api/jira/issues', async (req, res) => {
  const { projectKey, summary, description, issueType } = req.body;
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue`;
    const response = await axios.post(
      url,
      {
        fields: {
          project: { key: projectKey },
          summary,
          description,
          issuetype: { name: issueType || 'Task' }
        }
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.jiraAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error creating Jira issue:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to create Jira issue', details: err?.response?.data });
  }
});

// Transition a Jira issue
app.post('/api/jira/issues/:issueIdOrKey/transition', async (req, res) => {
  const { transitionId } = req.body;
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue/${req.params.issueIdOrKey}/transitions`;
    const response = await axios.post(
      url,
      { transition: { id: transitionId } },
      {
        headers: {
          Authorization: `Bearer ${req.session.jiraAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error transitioning issue:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to transition issue' });
  }
});

// -------------------- Confluence Endpoints --------------------

// GET /api/confluence/spaces
app.get('/api/confluence/spaces', async (req, res) => {
  if (!req.session.confluenceAccessToken || !req.session.confluenceSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Confluence' });
  }
  try {
    const url = `https://api.atlassian.com/ex/confluence/${req.session.confluenceSiteId}/wiki/rest/api/space?limit=50`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${req.session.confluenceAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Confluence spaces:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Confluence spaces' });
  }
});

// POST /api/confluence/pages (create a page)
app.post('/api/confluence/pages', async (req, res) => {
  if (!req.session.confluenceAccessToken || !req.session.confluenceSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Confluence' });
  }
  const { spaceKey, title, content } = req.body;
  if (!spaceKey || !title) {
    return res.status(400).json({ error: 'spaceKey and title are required' });
  }
  try {
    const url = `https://api.atlassian.com/ex/confluence/${req.session.confluenceSiteId}/wiki/rest/api/content`;
    const response = await axios.post(
      url,
      {
        type: 'page',
        title,
        space: { key: spaceKey },
        body: {
          storage: {
            value: content || ' ',
            representation: 'storage'
          }
        }
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.confluenceAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error creating Confluence page:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to create Confluence page' });
  }
});

// -------------------- Serve your main Projects HTML (if needed) --------------------
app.get('/projects.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'projects.html'));
});

// -------------------- Start Server --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
