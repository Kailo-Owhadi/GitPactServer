require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/gitpact', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const ProjectSchema = new mongoose.Schema({
  name: String,
  owner: String,
  status: String,
  deadline: Date,
  description: String,
  jiraProjectId: String
});

const Project = mongoose.model('Project', ProjectSchema);

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallbackSecret',
  resave: false,
  saveUninitialized: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/auth/jira', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  res.redirect(`https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID || 'omRjVfp6XFBBj7RcKYQNiaUYjLj1Q1Lr'}&scope=read%3Ajira-work%20manage%3Ajira-project%20manage%3Ajira-configuration%20read%3Ajira-user%20write%3Ajira-work%20manage%3Ajira-webhook%20manage%3Ajira-data-provider&redirect_uri=${encodeURIComponent(process.env.ATLASSIAN_REDIRECT_URI || 'https://gitpactserver.onrender.com/auth/jira/callback')}&state=${state}&response_type=code&prompt=consent`);
});

app.get('/auth/jira/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('Missing code parameter.');
  if (state !== req.session.oauthState) return res.status(403).send('Invalid state parameter.');
  try {
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
    const resourcesResp = await axios.get('https://api.atlassian.com/oauth/token/accessible-resources', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const sites = resourcesResp.data;
    if (sites.length > 0) {
      req.session.jiraSiteId = sites[0].id;
      req.session.jiraSiteUrl = sites[0].url;
    }
    res.redirect('https://gitpactserver.onrender.com/projects1.html');
  } catch (err) {
    console.error('Error exchanging code for token:', err?.response?.data || err.message);
    res.status(500).send('Failed to get access token from Atlassian');
  }
});

app.get('/api/jira/status', (req, res) => {
  if (req.session.jiraAccessToken && req.session.jiraSiteId) {
    return res.json({ connected: true });
  }
  return res.json({ connected: false });
});

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
    return res.json(response.data);
  } catch (err) {
    console.error('Error fetching Jira projects:', err?.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to fetch Jira projects' });
  }
});

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
    return res.status(500).json({ error: 'Failed to create Jira issue', details: err?.response?.data });
  }
});

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

app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find();
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.post('/api/projects', async (req, res) => {
  try {
    const project = new Project(req.body);
    await project.save();
    res.status(201).json(project);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create project' });
  }
});

app.put('/api/projects/:id', async (req, res) => {
  try {
    const project = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update project' });
  }
});

app.delete('/api/projects/:id', async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

app.post('/api/search', async (req, res) => {
  const { query } = req.body;
  try {
    const [jiraResults, localProjects] = await Promise.all([
      axios.get(`https://api.atlassian.com/ex/jira/${req.session.jiraSiteId}/rest/api/3/search?jql=${encodeURIComponent(`text ~ "${query}"`)}`, {
        headers: { Authorization: `Bearer ${req.session.jiraAccessToken}` }
      }),
      Project.find({ $text: { $search: query } })
    ]);
    res.json({
      jira: jiraResults.data.issues,
      local: localProjects
    });
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});