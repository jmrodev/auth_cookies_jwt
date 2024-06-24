// ** app.js **

import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import express from 'express'
const app = express()

const jwtSecret = 'your_jwt_secret'

app.use(bodyParser.json())
app.use(cookieParser())

const users = []

// Middleware para verificar la autenticación del usuario
const verifyAuth = (req, res, next) => {
  const token = req.cookies.token

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized' })
    }

    req.user = users.find((user) => user.email === decoded.email)
    next()
  })
}

// Ruta para registrar un nuevo usuario
app.post('/register', (req, res) => {
  const { email, password } = req.body

  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ message: 'User already exists' })
  }

  users.push({ email, password })
  res.status(201).json({ message: 'User registered successfully' })
})

// Ruta para iniciar sesión
app.post('/login', (req, res) => {
  const { email, password } = req.body

  const user = users.find(
    (user) => user.email === email && user.password === password
  )

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  const token = jwt.sign({ email }, jwtSecret)
  res.cookie('token', token, { httpOnly: true }).sendStatus(200)
})

// Ruta protegida que requiere autenticación
app.get('/protected', verifyAuth, (req, res) => {
  res.json({ message: `Welcome, ${req.user.email}!` })
})

app.listen(3000, () => {
  console.log('Server running on port 3000')
})
