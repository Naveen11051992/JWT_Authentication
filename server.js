require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const app = express()
app.use(express.json())

const users = []
const NO_OF_ROUNDS = 10

//get all the users
app.get('/users', authenticateToken, (req, res) => {
  res.json(users)
})

// register a user
app.post('/register', async (req, res) => {
  const userCheck = users.find((user) => {
    user.name = req.body.name
  })
  if (userCheck) {
    return res.status(409).send('user name or email exits')
  }
  try {
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
    const hashedPassword = await bcrypt.hash(req.body.password, salt)
    const user = {
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    }
    users.push(user)
    res.status(201).send()
  } catch {
    res.status(500).send()
  }
})

// login
app.post('/login', async (req, res) => {
  const userCheck = await users.find((user) => (user.name = req.body.name))
  if (!userCheck) {
    return res.status(409).send('Cannot find the user')
  }
  try {
    if (await bcrypt.compare(req.body.password, userCheck.password)) {
      const accessToken = jwt.sign(
        userCheck.name,
        process.env.ACCESS_TOKEN_SECRET
      )
      res.json({
        accessToken: accessToken,
      })
    } else {
      res.status(200).send('Not Allowed')
    }
  } catch {
    res.status(500).send()
  }
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']

  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.listen(5000)
