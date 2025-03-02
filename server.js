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

// -------------------- Atlassian OAuth (Jira + Confluence) --------------------
// Shared logic because the tokens are valid across Atlassian products if scopes allow it.

// Step 1: Redirect user to Atlassian login for OAuth consent (Jira)
app.get('/auth/jira', (req, res) => {
  // Generate a unique state value and store it in the session
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;

  // Scopes needed for Jira
  const scopes = encodeURIComponent('read:jira-work manage:jira-project manage:jira-configuration read:jira-user write:jira-work manage:jira-webhook manage:jira-data-provider');

  res.redirect(
    `https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${
      process.env.ATLASSIAN_CLIENT_ID
    }&scope=${scopes}&redirect_uri=${encodeURIComponent(
      process.env.ATLASSIAN_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/jira/callback'
    )}&state=${state}&response_type=code&prompt=consent`
  );
});

// Step 2: Handle callback for Jira and exchange code for tokens
app.get('/auth/jira/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).send('Missing code parameter.');
  }
  if (state !== req.session.oauthState) {
    return res.status(403).send('Invalid state parameter.');
  }
  try {
    const tokenResponse = await axios.post('https://auth.atlassian.com/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
      code,
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/jira/callback'
    });

    const { access_token, refresh_token } = tokenResponse.data;
    req.session.atlassianAccessToken = access_token;
    req.session.atlassianRefreshToken = refresh_token;

    // Retrieve accessible resources for the user (Jira & Confluence)
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    const sites = resourcesResp.data;
    // Typically, "sites" includes both Jira and Confluence if available
    // For simplicity, store the first Jira site info
    const jiraSite = sites.find(s => s.scopes.includes('READ:JIRA-WORK'));
    if (jiraSite) {
      req.session.jiraSiteId = jiraSite.id;
      req.session.jiraSiteUrl = jiraSite.url;
    }

    // Also check for a Confluence site
    const confluenceSite = sites.find(s => s.scopes.includes('READ:CONFLUENCE-SITE'));
    if (confluenceSite) {
      req.session.confluenceSiteId = confluenceSite.id;
      req.session.confluenceSiteUrl = confluenceSite.url;
    }

    res.redirect('https://gitpactserver.onrender.com/projects1.html');
  } catch (err) {
    console.error('Error exchanging code for token:', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian');
  }
});

// Confluence Auth flow can be identical if you want a separate entry point
// or you can rely on the same tokens if scopes for Confluence are already requested.
// We'll create a separate route for clarity, though it can be merged in real apps.

app.get('/auth/confluence', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.confluenceOauthState = state;

  // Scopes needed for Confluence
  // You can combine them all in one big scope, but shown separately here
  const scopes = encodeURIComponent('read:confluence-space read:confluence-props write:confluence-props read:confluence-content write:confluence-content');

  res.redirect(
    `https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${
      process.env.ATLASSIAN_CLIENT_ID
    }&scope=${scopes}&redirect_uri=${encodeURIComponent(
      process.env.ATLASSIAN_CONFLUENCE_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/confluence/callback'
    )}&state=${state}&response_type=code&prompt=consent`
  );
});

app.get('/auth/confluence/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    return res.status(400).send('Missing code parameter.');
  }
  if (state !== req.session.confluenceOauthState) {
    return res.status(403).send('Invalid state parameter.');
  }
  try {
    const tokenResponse = await axios.post('https://auth.atlassian.com/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
      code,
      redirect_uri: process.env.ATLASSIAN_CONFLUENCE_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/confluence/callback'
    });

    const { access_token, refresh_token } = tokenResponse.data;

    // We can store them in the same session fields or separate
    req.session.atlassianAccessToken = access_token;
    req.session.atlassianRefreshToken = refresh_token;

    // Retrieve accessible resources (including Confluence)
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    const sites = resourcesResp.data;

    const confluenceSite = sites.find(s => s.scopes.includes('READ:CONFLUENCE-SITE'));
    if (confluenceSite) {
      req.session.confluenceSiteId = confluenceSite.id;
      req.session.confluenceSiteUrl = confluenceSite.url;
    }

    // Possibly re-check for Jira as well
    const jiraSite = sites.find(s => s.scopes.includes('READ:JIRA-WORK'));
    if (jiraSite) {
      req.session.jiraSiteId = jiraSite.id;
      req.session.jiraSiteUrl = jiraSite.url;
    }

    res.redirect('https://gitpactserver.onrender.com/projects1.html');
  } catch (err) {
    console.error('Error exchanging code for token:', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian (Confluence)');
  }
});

// -------------------- Jira Endpoints --------------------
app.get('/api/jira/status', (req, res) => {
  if (req.session.atlassianAccessToken && req.session.jiraSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

// GET /api/jira/projects – Fetch Jira projects
app.get('/api/jira/projects', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const projectsUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project`;
    const response = await axios.get(projectsUrl, {
      headers: {
        Authorization: `Bearer ${req.session.atlassianAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira projects:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira projects' });
  }
});

// CREATE /api/jira/projects – Create a new Jira project
app.post('/api/jira/projects', async (req, res) => {
  const { name, key, leadAccountId, projectTypeKey } = req.body;
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project`;
    const response = await axios.post(
      url,
      {
        key,
        name,
        projectTypeKey: projectTypeKey || 'software',
        leadAccountId
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.atlassianAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error creating Jira project:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to create Jira project', details: err?.response?.data });
  }
});

// UPDATE /api/jira/projects/:projectIdOrKey – Edit a Jira project
app.put('/api/jira/projects/:projectIdOrKey', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  const { name, key } = req.body;
  const projectIdOrKey = req.params.projectIdOrKey;

  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/project/${projectIdOrKey}`;
    const response = await axios.put(
      url,
      {
        key,
        name
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.atlassianAccessToken}`,
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

// GET /api/jira/issue/:issueId – Fetch detailed info for a single Jira issue
app.get('/api/jira/issue/:issueId', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const issueUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue/${req.params.issueId}`;
    const response = await axios.get(issueUrl, {
      headers: {
        Authorization: `Bearer ${req.session.atlassianAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira issue:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira issue details' });
  }
});

// GET /api/jira/issues – Fetch Jira issues
app.get('/api/jira/issues', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Jira' });
  }
  try {
    const issuesUrl = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/search`;
    const response = await axios.get(issuesUrl, {
      headers: {
        Authorization: `Bearer ${req.session.atlassianAccessToken}`,
        'Accept': 'application/json'
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira issues:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira issues' });
  }
});

// POST /api/jira/issues – Create a new Jira issue
app.post('/api/jira/issues', async (req, res) => {
  const { projectKey, summary, description, issueType } = req.body;
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
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
          Authorization: `Bearer ${req.session.atlassianAccessToken}`,
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

// POST /api/jira/issues/:issueIdOrKey/transition – Transition a Jira issue (optional)
app.post('/api/jira/issues/:issueIdOrKey/transition', async (req, res) => {
  const { transitionId } = req.body;
  if (!req.session.atlassianAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  try {
    const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue/${req.params.issueIdOrKey}/transitions`;
    const response = await axios.post(
      url,
      { transition: { id: transitionId } },
      {
        headers: {
          Authorization: `Bearer ${req.session.atlassianAccessToken}`,
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
app.get('/api/confluence/status', (req, res) => {
  if (req.session.atlassianAccessToken && req.session.confluenceSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

// GET /api/confluence/spaces – fetch Confluence spaces
app.get('/api/confluence/spaces', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.confluenceSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Confluence' });
  }
  try {
    const url = `https://api.atlassian.com/ex/confluence/${req.session.confluenceSiteId}/wiki/rest/api/space`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${req.session.atlassianAccessToken}`,
        'Accept': 'application/json'
      },
      params: {
        limit: 50
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Confluence spaces:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Confluence spaces' });
  }
});

// GET /api/confluence/pages – fetch Confluence pages (content)
app.get('/api/confluence/pages', async (req, res) => {
  if (!req.session.atlassianAccessToken || !req.session.confluenceSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Confluence' });
  }
  try {
    // We'll fetch the first 50 pages
    const url = `https://api.atlassian.com/ex/confluence/${req.session.confluenceSiteId}/wiki/rest/api/content`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${req.session.atlassianAccessToken}`,
        'Accept': 'application/json'
      },
      params: {
        limit: 50
      }
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Confluence pages:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Confluence pages' });
  }
});

// POST /api/confluence/pages – create Confluence page
app.post('/api/confluence/pages', async (req, res) => {
  const { spaceKey, title, content } = req.body;
  if (!req.session.atlassianAccessToken || !req.session.confluenceSiteId) {
    return res.status(401).json({ error: 'User not authenticated with Confluence' });
  }
  if (!spaceKey || !title || !content) {
    return res.status(400).json({ error: 'spaceKey, title, and content are required.' });
  }
  try {
    const url = `https://api.atlassian.com/ex/confluence/${req.session.confluenceSiteId}/wiki/rest/api/content`;
    const response = await axios.post(url,
      {
        type: 'page',
        title,
        space: { key: spaceKey },
        body: {
          storage: {
            value: content,
            representation: 'storage'
          }
        }
      },
      {
        headers: {
          Authorization: `Bearer ${req.session.atlassianAccessToken}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return res.json(response.data);
  } catch (err) {
    console.error('Error creating Confluence page:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to create Confluence page', details: err?.response?.data });
  }
});

// -------------------- Start Server --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
