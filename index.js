/*
  ===================
  Vocabulario Backend
  ===================
  Simple Node.js / Express based backend API for the vocabulary trainer vocabulario
  See README for further information
                                                                                    */

// Include Express basics
const express = require('express')
const cors = require('cors')

// Include fortuneHTTP
const fortune = require('fortune')
const fortuneHTTP = require('fortune-http')
const jsonApiSerializer = require('fortune-json-api')
const mongodbAdapter = require('fortune-mongodb')
const ShortUniqueId = require('short-unique-id')

// Include authentication libraries
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

// Load env variables
require("dotenv").config()

// Use fortune API
const typeMap = { vocabulary: 'vocabularies', training: 'trainings', user: 'users' }
const store = fortune(
  {
    vocabulary: {
      name: String,
      article: String,
      language: String,
      translatedLanguages: Array(String),
      translations: [ Array('vocabulary'), 'translations' ],
      user: [ 'user', 'vocabularies' ]
    },
    training: {
      start: Date,
      end: Date,
      sourceLang: String,
      targetLang: String,
      amount: Number,
      scores: Array(Number),
      statistics: Array(Object),
      vocabularies: [ Array('vocabulary') ],
      user: [ 'user', 'trainings' ]
    },
    user: {
      name: String,
      email: String,
      password: String,
      token: String,
      trainings: [ Array('training'), 'user' ],
      vocabularies: [ Array('vocabulary'), 'user' ]
    }
  },
  {
    adapter: [
      mongodbAdapter, {
        url: process.env.DATABASE_URL,
        useUnifiedTopology: true,
        generateId: setId,
        typeMap: typeMap
      }
    ],
    hooks: {
      user: [ register ],
      training: [ undefined, statistics ]
    }
  }
)
const listener = fortuneHTTP(store, {
  serializers: [
    [ jsonApiSerializer ]
  ]
})

// Use Express as middleware
const app = express()
app.use(express.json())
app.use(cors())

// Sign in
app.post('/api/token-auth', ensureApiKey, async function (request, response) {
  const { email, password } = request.body
  if (email && password) {
    const result = await store.find('user', undefined, { match: { email: email }})
    if (result.payload && result.payload.records && result.payload.records.length > 0) {
      let user = result.payload.records[0]
      if ((await bcrypt.compare(password, user.password))) {
        const res = await generateToken(user)
        return response.json(res)
      }
    }
  }
  return response.status(403).json({ error: "Authentication failed. Username and/or password did not match our records." })
})

// Refresh token
app.post('/api/token-refresh', async function (request, response) {
  const { token } = request.body
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.TOKEN_KEY)
      const res = await generateToken({ id: decoded.user_id, email: decoded.email })
      return response.json(res)
    } catch (err) {
      return response.status(401).json({ error: "Invalid token. Please re-authenticate." })
    }
  }
})

// Hook up fortuneHTTP
app.use(/^\/api\/1/, ensureApiKey, auth, (request, response) =>
  listener(request, response)
  .catch(error => { console.log(error) }))

// API listens on port 3000
app.listen(3000, function () {
  console.log('Vocabulario Backend listening on port 3000')
})


/*
  ====================
  Supporting functions
  ====================
                    */

// Ensure api key is present and valid
function ensureApiKey(request, response, next) {
  const apikey = request.headers["x-api-key"]
  if (!apikey || apikey != process.env.API_KEY) {
    return response.status(400).json({ error: "API key missing or invalid." })
  }
  return next()
}

// Ensure valid token is present on certain routes
function auth(request, response, next) {
  if (!['/api/1/users'].includes(request._parsedUrl.pathname)) {
    const token = request.headers["authorization"]
    if (!token) {
      return response.status(403).json({ error: "Token missing. Please authenticate and include returned token in header." })
    }
    try {
      const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.TOKEN_KEY)
    } catch (err) {
      return response.status(401).json({ error: "Invalid token. Please re-authenticate." })
    }
  }
  return next()
}

// Generate Token
async function generateToken(user) {
  const token = jwt.sign({ user_id: user.id, email: user.email }, process.env.TOKEN_KEY, { expiresIn: "5m" })
  await store.update('user', { id: user.id, replace: { token: token }})
  return { token: token }
}

// Set UUID for every new record created
function setId(type) {
  const uid = new ShortUniqueId({ length: 10 })
  return uid()
}

// Handle: Encrypt password for every new user
async function register(context, record, update) {
  if (context.request.method == 'create') {
    record.password = await bcrypt.hash(record.password, 10)
    return record
  }
}

// Handle: Return pre-calculated statistics
async function statistics(context, record) {
  let promises = record['vocabularies'].map((id, i) => {
    return store.find('vocabulary', id).then((result) => {
      let vocabulary = result.payload.records[0]
      return { id: vocabulary.id, name: vocabulary.name, score: record['scores'][i] }
    })
  })
  record['statistics'] = await Promise.all(promises).then(function(results) {
    return results
  })
  return record;
}
