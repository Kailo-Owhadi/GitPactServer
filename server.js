// server.js
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

// -------------------- OAuth Flow --------------------

// Step 1: Redirect user to Atlassian login for OAuth consent
app.get('/auth/jira', (req, res) => {
    // Generate a unique state value and store it in the session
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;
  
   /* const authorizationUrl = 'https://auth.atlassian.com/authorize';
    const scopes = [
      'read:jira-work',
      'write:jira-work',
      'read:jira-user'
    ].join(' ');
    const queryParams = new URLSearchParams({
      audience: 'api.atlassian.com',
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      scope: scopes,
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI,
      response_type: 'code',
      prompt: 'consent',
      state: state
    });
    const oauthUrl = `${authorizationUrl}?${queryParams.toString()}`;
    console.log("Redirecting to OAuth URL:", oauthUrl);*/
    console.log('redirecting');
    res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr&scope=read%3Ajira-work%20manage%3Ajira-project%20manage%3Ajira-configuration%20read%3Ajira-user%20write%3Ajira-work%20manage%3Ajira-webhook%20manage%3Ajira-data-provider&redirect_uri=${encodeURIComponent('https://gitpactserver.onrender.com/auth/jira/callback')}&state=${state}&response_type=code&prompt=consent`);
    //res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID}&scope=read%3Ajira-work%20manage%3Ajira-project%20manage%3Ajira-configuration%20read%3Ajira-user%20write%3Ajira-work%20manage%3Ajira-webhook%20manage%3Ajira-data-provider&redirect_uri=${encodeURIComponent(process.env.ATLASSIAN_REDIRECT_URI)}&state=${state}&response_type=code&prompt=consent`);
});

// Step 2: Handle callback and exchange code for tokens
app.get('/auth/jira/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) {
    console.log('missing param');
    return res.status(400).send('Missing code parameter.');
  }
  /*if (state !== req.session.oauthState) {
    console.log('missing state');
    return res.status(403).send('Invalid state parameter.');
  }*/
  try {
    const tokenResponse = await axios.post('https://auth.atlassian.com/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.ATLASSIAN_CLIENT_ID,
      client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
      code,
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI
    });
    console.log('got token?');
    const { access_token, refresh_token } = tokenResponse.data;
    req.session.jiraAccessToken = access_token;
    req.session.jiraRefreshToken = refresh_token;

    // Retrieve accessible Jira Cloud sites for the user
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    const sites = resourcesResp.data;
    if (sites.length > 0) {
      // For simplicity, store the first site the user can access
      req.session.jiraSiteId = sites[0].id;
      req.session.jiraSiteUrl = sites[0].url;
    }
    // After connection, redirect back to your projects page.
    console.log('now redirecting');
    res.redirect('https://gitpactserver.onrender.com/public/projects1.html');
  } catch (err) {
    console.error('Error exchanging code for token:', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian');
  }
});

// -------------------- Additional Endpoint --------------------
// This endpoint returns whether the user is connected to Jira.
app.get('/api/jira/status', (req, res) => {
  if (req.session.jiraAccessToken && req.session.jiraSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

// -------------------- API Endpoints --------------------

// GET /api/jira/issues – Fetch Jira issues
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

// POST /api/jira/issues – Create a new Jira issue
app.post('/api/jira/issues', async (req, res) => {
  const { projectKey, summary, description, issueType } = req.body;
  if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
    return res.status(401).json({ error: 'Not authenticated with Jira' });
  }
  const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue`;
  try {
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
    return res.status(500).json({ error: 'Failed to create Jira issue' });
  }
});

// POST /api/jira/issues/:issueIdOrKey/transition – Transition a Jira issue
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

// -------------------- Start Server --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
