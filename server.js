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
  console.log("Generated state:", state);

  res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr'}&scope=read%3Ajira-work%20manage%3Ajira-project%20manage%3Ajira-configuration%20read%3Ajira-user%20write%3Ajira-work%20manage%3Ajira-webhook%20manage%3Ajira-data-provider&redirect_uri=${encodeURIComponent(process.env.ATLASSIAN_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/jira/callback')}&state=${state}&response_type=code&prompt=consent`);
});

// Step 2: Handle callback and exchange code for tokens
app.get('/auth/jira/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) {
    console.log('Missing code parameter');
    return res.status(400).send('Missing code parameter.');
  }
  if (state !== req.session.oauthState) {
    console.log(`Invalid state: received ${state}, expected ${req.session.oauthState}`);
    return res.status(403).send('Invalid state parameter.');
  }
  try {
    console.log("Exchanging code for token...");
    const tokenResponse = await axios.post('https://auth.atlassian.com/oauth/token', {
      grant_type: 'authorization_code',
      client_id: process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr',
      client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
      code,
      redirect_uri: process.env.ATLASSIAN_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/jira/callback'
    });
    const { access_token, refresh_token } = tokenResponse.data;
    req.session.jiraAccessToken = access_token;
    req.session.jiraRefreshToken = refresh_token;
    console.log("Received tokens.");

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
      console.log("Stored Jira site info:", sites[0]);
    }
    console.log("Redirecting to projects1.html");
    res.redirect('https://gitpactserver.onrender.com/projects1.html');
  } catch (err) {
    console.error('Error exchanging code for token:', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian');
  }
});

// -------------------- Additional Endpoints --------------------

// Endpoint to check Jira connection status
app.get('/api/jira/status', (req, res) => {
  if (req.session.jiraAccessToken && req.session.jiraSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

// GET /api/jira/projects – Fetch Jira projects
/*app.get('/api/jira/projects', async (req, res) => {
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
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira projects:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira projects' });
  }
});*/
app.post('/api/jira/projects', async (req, res) => {
    const { key, name, projectTypeKey, leadAccountId } = req.body;
    if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
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
            Authorization: `Bearer ${req.session.jiraAccessToken}`,
            'Content-Type': 'application/json'
          }
        }
      );
      return res.json(response.data);
    } catch (err) {
      console.error('Error creating project:', err.response?.data || err.message);
      return res.status(500).json({
        error: 'Failed to create project',
        details: err.response?.data || err.message
      });
    }
  });

// GET /api/jira/issue/:issueId – Fetch detailed info for a single Jira issue
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

// GET /api/jira/issues – Fetch Jira issues (using search endpoint)
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
/*app.post('/api/jira/issues', async (req, res) => {
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
    return res.status(500).json({ error: 'Failed to create Jira issue', details: err?.response?.data });
  }
});*/

app.post('/api/jira/issues', async (req, res) => {
    const { projectKey, summary, description, issueTypeId } = req.body;
    if (!req.session.jiraAccessToken || !req.session.jiraSiteId) {
      return res.status(401).json({ error: 'Not authenticated with Jira' });
    }
  
    // Convert description to ADF format
    const adfDescription = {
      type: 'doc',
      version: 1,
      content: [{
        type: 'paragraph',
        content: [{ type: 'text', text: description || '' }]
      }]
    };
  
    try {
      const url = `https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/issue`;
      const response = await axios.post(
        url,
        {
          fields: {
            project: { key: projectKey },
            summary: summary,
            description: adfDescription,
            issuetype: { name: "Task" },
           /* type: "standard",
            issueTypeId: "1",
            id: "1",
            name: "Task" // Use ID instead of name*/
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
      console.error('Error creating issue:', err.response?.data || err.message);
      return res.status(500).json({
        error: 'Failed to create issue',
        details: err.response?.data || err.message
      });
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
